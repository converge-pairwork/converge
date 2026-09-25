// The one place in the bridge that knows which operating system it is on.
//
// Everything else asks this header for the four things that actually differ: where this user's
// private CONVERGE state lives, what this process's identity is, whether some other process is
// still alive, and how to start a detached helper. Nothing else in the bridge contains a
// platform conditional or a platform-shaped path string, which is the point: a rule that lives
// in one function can be read, tested and changed; the same rule spelled out in nine places
// cannot.
//
// Where the state lives:
//
//   CONVERGE_HOME          set   use it, whatever the platform. Automated tests set this, and it
//                                is also the escape hatch for anyone whose home is not writable.
//   Windows                      %LOCALAPPDATA%\CONVERGE. Local, not Roaming, on purpose: this
//                                directory holds a private key and per-process live files, and
//                                a roaming profile would copy them between machines.
//   Linux, macOS                 ~/.converge, which is the existing convention and stays.
//
// Private state is created private on every platform, in the terms that platform has. On Unix
// that is 0700 for a directory and 0600 for a file. Windows has no mode bits, so the equivalent
// is written out in full: a protected discretionary ACL holding one entry, for this user, and
// nothing else. Protected is the word that matters, because %LOCALAPPDATA% being per-user does
// not stop an ACL inherited from a parent directory being wider than 0700 would be. Setting the
// DACL and refusing inheritance in the same call is what closes that.
#pragma once

#include <filesystem>
#include <string>
#include <string_view>
#include <system_error>
#include <vector>

#ifdef _WIN32
#include <process.h>
#include <windows.h>
#include <aclapi.h>
#include <accctrl.h>
#include <sddl.h>
#else
#include <csignal>
#include <cerrno>
#ifdef __APPLE__
#include <mach-o/dyld.h>
#endif
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <fcntl.h>
#endif

#include <cstdlib>

namespace converge::platform {

// A path as a std::string, and back again, without losing anything.
//
// The bridge carries a few paths as std::string: the identity file, the pin store, the saved
// connections. On Unix that is exactly the bytes of the path and costs nothing. On Windows a
// path is UTF-16, and std::filesystem's narrow conversions go through the process's ANSI code
// page, which cannot represent most of the world's names. A user whose profile is under
// "estado convergé" or "状態" would have their path quietly turned into question marks
// somewhere between reading the environment and opening the file, and no later care could put
// it back. These two say UTF-8 on both sides, so the round trip is lossless on every platform,
// and they are the only conversion between the two that the bridge performs.
inline std::string to_utf8(const std::filesystem::path& p) {
    const auto text = p.u8string();
    return std::string(text.begin(), text.end());
}

inline std::filesystem::path from_utf8(std::string_view text) {
    return std::filesystem::path(std::u8string(text.begin(), text.end()));
}

// One environment variable, as a path.
//
// On Windows this reads the wide environment deliberately. getenv() hands back the ANSI copy of
// it, in which a character the code page cannot represent has already become '?' before this
// process ever looked: the loss happens in the C runtime, not here, so reading it narrowly and
// converting afterwards cannot help. Variable names are ASCII, which is why widening the name
// is the one narrow conversion left.
inline std::filesystem::path env_path(const char* name) {
#ifdef _WIN32
    const std::wstring wide(name, name + std::char_traits<char>::length(name));
    const wchar_t* value = ::_wgetenv(wide.c_str());
    return (value && *value) ? std::filesystem::path(value) : std::filesystem::path();
#else
    const char* value = std::getenv(name);
    return (value && *value) ? std::filesystem::path(value) : std::filesystem::path();
#endif
}

// This user's home, as the platform names it. On Windows USERPROFILE is what Claude Code and
// Codex themselves expand "~" to, so this is also where their own configuration is found.
inline std::filesystem::path home() {
#ifdef _WIN32
    if (auto p = env_path("USERPROFILE"); !p.empty()) return p;
    const auto drive = env_path("HOMEDRIVE"), rest = env_path("HOMEPATH");
    if (!drive.empty() && !rest.empty()) return drive / rest.relative_path();
#endif
    if (auto p = env_path("HOME"); !p.empty()) return p;
    return std::filesystem::current_path();
}

// CONVERGE's own persistent state: the identity key, pinned peers, saved connections, the
// updater's record, and the live directory. See the note at the top of this file.
inline std::filesystem::path state_dir() {
    if (auto forced = env_path("CONVERGE_HOME"); !forced.empty()) return forced;
#ifdef _WIN32
    if (auto local = env_path("LOCALAPPDATA"); !local.empty()) return local / "CONVERGE";
    return home() / "AppData" / "Local" / "CONVERGE";
#else
    return home() / ".converge";
#endif
}

#ifdef _WIN32
// The SID of the user this process is running as, as a freshly allocated, self-contained copy.
// Returned by value so the caller owns it and the token buffer does not have to outlive it.
inline std::vector<unsigned char> current_user_sid() {
    HANDLE token = nullptr;
    if (!::OpenProcessToken(::GetCurrentProcess(), TOKEN_QUERY, &token)) return {};
    DWORD needed = 0;
    ::GetTokenInformation(token, TokenUser, nullptr, 0, &needed);
    std::vector<unsigned char> buffer(needed ? needed : 1);
    std::vector<unsigned char> sid;
    if (needed && ::GetTokenInformation(token, TokenUser, buffer.data(), needed, &needed)) {
        auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
        if (user->User.Sid && ::IsValidSid(user->User.Sid)) {
            const DWORD length = ::GetLengthSid(user->User.Sid);
            sid.resize(length);
            if (!::CopySid(length, sid.data(), user->User.Sid)) sid.clear();
        }
    }
    ::CloseHandle(token);
    return sid;
}

// Give `path` a discretionary ACL with exactly one entry, full control for this user, and mark
// it protected so that nothing is inherited from the parent. This is the Windows spelling of
// 0700 on a directory and 0600 on a file: everybody else, including other members of the user's
// groups and any wider ACE the parent would have handed down, is left with no access at all.
//
// A directory also gets that entry as an inheritable one, so files CONVERGE creates inside it
// (an identity key, the pinned peers, a live acknowledgement) are private from the moment they
// exist rather than from the moment something remembers to tighten them.
//
// Returns whether the ACL is now the one described. A false here means the state is no more
// private than the platform's default, which the caller may want to say out loud; it is never a
// reason to throw, because every caller is on a path where failing loudly is worse.
inline bool restrict_to_owner(const std::filesystem::path& path, bool inheritable) {
    const std::vector<unsigned char> sid = current_user_sid();
    if (sid.empty()) return false;
    EXPLICIT_ACCESS_W access{};
    access.grfAccessPermissions = GENERIC_ALL;
    access.grfAccessMode = SET_ACCESS;
    access.grfInheritance = inheritable ? (CONTAINER_INHERIT_ACE | OBJECT_INHERIT_ACE) : NO_INHERITANCE;
    access.Trustee.TrusteeForm = TRUSTEE_IS_SID;
    access.Trustee.TrusteeType = TRUSTEE_IS_USER;
    access.Trustee.ptstrName = reinterpret_cast<LPWSTR>(const_cast<unsigned char*>(sid.data()));
    PACL acl = nullptr;
    if (::SetEntriesInAclW(1, &access, nullptr, &acl) != ERROR_SUCCESS) return false;
    const std::wstring name = path.wstring();
    const DWORD rc = ::SetNamedSecurityInfoW(const_cast<LPWSTR>(name.c_str()), SE_FILE_OBJECT,
                                             DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                                             nullptr, nullptr, acl, nullptr);
    if (acl) ::LocalFree(acl);
    return rc == ERROR_SUCCESS;
}
#endif

// Create a directory only this user can read. Never throws: a caller of this is always on a
// path where failing quietly is better than failing loudly.
inline void make_private_dir(const std::filesystem::path& dir) {
    std::error_code ec;
    std::filesystem::create_directories(dir, ec);
#ifdef _WIN32
    restrict_to_owner(dir, true);
#else
    std::filesystem::permissions(dir, std::filesystem::perms::owner_all,
                                 std::filesystem::perm_options::replace, ec);
#endif
}

// The same for one file that already exists: the identity key, the pinned peers, the saved
// connections. On Unix std::filesystem::permissions says this exactly; on Windows it does not,
// because the standard library there maps a mode onto the read-only attribute and no further,
// which is why this is spelled out rather than left to perms::owner_read.
inline void make_private_file(const std::filesystem::path& file) {
    std::error_code ec;
#ifdef _WIN32
    restrict_to_owner(file, false);
#else
    std::filesystem::permissions(file, std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                                 std::filesystem::perm_options::replace, ec);
#endif
}

// Is this path private to this user alone, as the platform understands that? The question the
// tests ask, answered by the same code that sets it, so that a platform whose implementation
// silently does nothing cannot pass.
inline bool is_private(const std::filesystem::path& path) {
#ifdef _WIN32
    PACL acl = nullptr;
    PSECURITY_DESCRIPTOR descriptor = nullptr;
    const std::wstring name = path.wstring();
    if (::GetNamedSecurityInfoW(name.c_str(), SE_FILE_OBJECT, DACL_SECURITY_INFORMATION,
                                nullptr, nullptr, &acl, nullptr, &descriptor) != ERROR_SUCCESS)
        return false;
    const std::vector<unsigned char> sid = current_user_sid();
    bool only_us = acl != nullptr && !sid.empty();
    if (only_us) {
        for (DWORD i = 0; i < acl->AceCount; ++i) {
            void* raw = nullptr;
            if (!::GetAce(acl, i, &raw)) { only_us = false; break; }
            auto* header = static_cast<ACE_HEADER*>(raw);
            if (header->AceType != ACCESS_ALLOWED_ACE_TYPE) { only_us = false; break; }
            auto* ace = static_cast<ACCESS_ALLOWED_ACE*>(raw);
            if (!::EqualSid(reinterpret_cast<PSID>(&ace->SidStart),
                            reinterpret_cast<PSID>(const_cast<unsigned char*>(sid.data())))) {
                only_us = false;
                break;
            }
        }
    }
    if (descriptor) ::LocalFree(descriptor);
    return only_us;
#else
    std::error_code ec;
    const auto status = std::filesystem::status(path, ec);
    if (ec) return false;
    using std::filesystem::perms;
    return (status.permissions() & (perms::group_all | perms::others_all)) == perms::none;
#endif
}

// This process, for the name of its own live-acknowledgement file.
inline unsigned long process_id() {
#ifdef _WIN32
    return static_cast<unsigned long>(::GetCurrentProcessId());
#else
    return static_cast<unsigned long>(::getpid());
#endif
}

// Is some process with this id still running? Used only to decide whether a leftover file may be
// removed, so "not sure" must mean "leave it alone": a false positive costs one stale file, a
// false negative would delete a live bridge's acknowledgements.
inline bool process_alive(unsigned long pid) {
    if (pid == 0) return true;
#ifdef _WIN32
    HANDLE h = ::OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, static_cast<DWORD>(pid));
    if (!h) return ::GetLastError() != ERROR_INVALID_PARAMETER;   // access denied: alive, not ours
    DWORD code = 0;
    const bool alive = !::GetExitCodeProcess(h, &code) || code == STILL_ACTIVE;
    ::CloseHandle(h);
    return alive;
#else
    return ::kill(static_cast<pid_t>(pid), 0) == 0 || errno != ESRCH;
#endif
}

// This executable, as a path. The bridge starts itself for the update check and registers
// itself as the MCP server and as the host's live-render hook, so it has to know where it is.
inline std::filesystem::path executable_path() {
#ifdef _WIN32
    std::wstring buffer(32768, L'\0');
    const DWORD n = ::GetModuleFileNameW(nullptr, buffer.data(), static_cast<DWORD>(buffer.size()));
    if (n == 0 || n >= buffer.size()) return {};
    buffer.resize(n);
    return std::filesystem::path(buffer);
#elif defined(__APPLE__)
    std::uint32_t size = 0;
    ::_NSGetExecutablePath(nullptr, &size);
    std::string buffer(size + 1, '\0');
    if (::_NSGetExecutablePath(buffer.data(), &size) != 0) return {};
    buffer.resize(std::char_traits<char>::length(buffer.c_str()));
    std::error_code ec;
    auto canonical = std::filesystem::canonical(buffer, ec);
    return ec ? std::filesystem::path(buffer) : canonical;
#else
    std::error_code ec;
    auto self = std::filesystem::read_symlink("/proc/self/exe", ec);
    return ec ? std::filesystem::path() : self;
#endif
}

// A program on PATH, by name, or empty. Windows resolves the extensions PATHEXT lists (the AI
// hosts' command line tools there are .cmd files), Unix looks for the name itself.
inline std::filesystem::path which(std::string_view name) {
    if (name.find_first_of("/\\") != std::string_view::npos) {
        std::error_code ec;
        return std::filesystem::is_regular_file(from_utf8(name), ec) ? from_utf8(name) : std::filesystem::path();
    }
    const auto path = env_path("PATH").string();
#ifdef _WIN32
    const char separator = ';';
    std::vector<std::string> extensions{"", ".exe", ".cmd", ".bat", ".com"};
#else
    const char separator = ':';
    std::vector<std::string> extensions{""};
#endif
    std::size_t start = 0;
    while (start <= path.size()) {
        const auto stop = path.find(separator, start);
        const auto dir = path.substr(start, stop == std::string::npos ? std::string::npos : stop - start);
        if (!dir.empty()) {
            for (const auto& ext : extensions) {
                const auto candidate = from_utf8(dir) / from_utf8(std::string(name) + ext);
                std::error_code ec;
                if (std::filesystem::is_regular_file(candidate, ec)) return candidate;
            }
        }
        if (stop == std::string::npos) break;
        start = stop + 1;
    }
    return {};
}

// Runs a program with these arguments (argv[0] is the program) and waits for it. Its standard
// streams are discarded: nothing a child prints may reach the MCP stream that owns this
// process's stdout. Returns the exit code, or -1 when it could not be started.
inline int run_and_wait(const std::vector<std::string>& argv) {
    if (argv.empty()) return -1;
#ifdef _WIN32
    // One command line, quoted the way the C runtime parses it back into argv.
    std::string line;
    for (const auto& a : argv) {
        if (!line.empty()) line += ' ';
        std::string q = "\"";
        unsigned backslashes = 0;
        for (const char c : a) {
            if (c == '\\') { ++backslashes; continue; }
            if (c == '"') { q.append(backslashes * 2 + 1, '\\'); q += '"'; backslashes = 0; continue; }
            q.append(backslashes, '\\'); backslashes = 0; q += c;
        }
        q.append(backslashes * 2, '\\');
        line += q + "\"";
    }
    SECURITY_ATTRIBUTES sa{}; sa.nLength = sizeof sa; sa.bInheritHandle = TRUE;
    HANDLE null = ::CreateFileA("NUL", GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, &sa, OPEN_EXISTING, 0, nullptr);
    STARTUPINFOA si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
    si.hStdInput = si.hStdOutput = si.hStdError = null;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    // A .cmd or .bat runs through the command interpreter; CreateProcess does not do that alone.
    const auto program = from_utf8(argv[0]).extension().string();
    std::string mutable_line = (program == ".cmd" || program == ".bat") ? "cmd.exe /d /c " + line : line;
    const BOOL ok = ::CreateProcessA(nullptr, mutable_line.data(), nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    if (null != INVALID_HANDLE_VALUE) ::CloseHandle(null);
    if (!ok) return -1;
    ::WaitForSingleObject(pi.hProcess, INFINITE);
    DWORD code = 0;
    ::GetExitCodeProcess(pi.hProcess, &code);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
    return static_cast<int>(code);
#else
    std::vector<std::string> copy = argv;
    std::vector<char*> cargv;
    for (auto& a : copy) cargv.push_back(a.data());
    cargv.push_back(nullptr);
    const pid_t pid = ::fork();
    if (pid < 0) return -1;
    if (pid == 0) {
        const int null = ::open("/dev/null", O_RDWR);
        if (null >= 0) { ::dup2(null, 0); ::dup2(null, 1); ::dup2(null, 2); if (null > 2) ::close(null); }
        ::execvp(cargv[0], cargv.data());
        ::_exit(127);
    }
    int status = 0;
    if (::waitpid(pid, &status, 0) < 0) return -1;
    if (WIFEXITED(status)) return WEXITSTATUS(status);
    return -1;
#endif
}

// Starts this executable again with these arguments and does not depend on it. The update check
// is the only user: CONVERGE must never wait on it, so every failure here is silent and simply
// means no update was attempted. `wait_sec` 0 detaches completely; anything larger waits up to
// that long for the helper to finish, then leaves it running.
inline void run_self_detached(const std::vector<std::string>& args, int wait_sec) {
    const auto self = executable_path();
    if (self.empty()) return;
#ifdef _WIN32
    std::string line = "\"" + to_utf8(self) + "\"";
    for (const auto& a : args) line += " \"" + a + "\"";
    STARTUPINFOA si{};
    si.cb = sizeof si;
    si.dwFlags = STARTF_USESHOWWINDOW;
    si.wShowWindow = SW_HIDE;
    PROCESS_INFORMATION pi{};
    if (!::CreateProcessA(nullptr, line.data(), nullptr, nullptr, FALSE, CREATE_NO_WINDOW | DETACHED_PROCESS, nullptr, nullptr, &si, &pi)) return;
    if (wait_sec > 0) ::WaitForSingleObject(pi.hProcess, static_cast<DWORD>(wait_sec) * 1000);
    ::CloseHandle(pi.hThread);
    ::CloseHandle(pi.hProcess);
#else
    const std::string path = to_utf8(self);
    std::vector<std::string> copy{path};
    copy.insert(copy.end(), args.begin(), args.end());
    std::vector<char*> cargv;
    for (auto& a : copy) cargv.push_back(a.data());
    cargv.push_back(nullptr);
    const pid_t pid = ::fork();
    if (pid < 0) return;
    if (pid == 0) {
        // Out of this process group, and with stdout well away from the MCP stream that owns our
        // fd 1. For the unwaited case a second fork hands the helper to init.
        if (::setsid() == -1) ::_exit(0);
        if (wait_sec <= 0 && ::fork() != 0) ::_exit(0);
        const int null = ::open("/dev/null", O_RDWR);
        if (null >= 0) { ::dup2(null, 0); ::dup2(null, 1); ::dup2(null, 2); if (null > 2) ::close(null); }
        ::execv(cargv[0], cargv.data());
        ::_exit(0);
    }
    int status = 0;
    if (wait_sec <= 0) { ::waitpid(pid, &status, 0); return; }      // the intermediate child, gone at once
    for (int waited = 0; waited < wait_sec * 20; ++waited) {
        if (::waitpid(pid, &status, WNOHANG) != 0) return;
        ::usleep(50'000);
    }
    ::waitpid(pid, &status, WNOHANG);   // still going: leave it to finish on its own
#endif
}

// ---- what the installer, the updater and the setup need from the platform ------------------

inline constexpr bool windows =
#ifdef _WIN32
    true;
#else
    false;
#endif

// This machine, in the words a CONVERGE release manifest uses (<os>-<arch>), or empty when
// CONVERGE publishes no bridge for it, which is not an error: such an installation updates its
// skill and leaves the bridge the user built themselves alone.
inline const char* release_platform() {
#if defined(_WIN32) && (defined(_M_X64) || defined(__x86_64__))
    return "windows-x86_64";
#elif defined(__APPLE__) && defined(__aarch64__)
    return "macos-arm64";
#elif defined(__APPLE__) && defined(__x86_64__)
    return "macos-x86_64";
#elif defined(__linux__) && defined(__x86_64__)
    return "linux-x86_64";
#elif defined(__linux__) && defined(__aarch64__)
    return "linux-arm64";
#else
    return "";
#endif
}

// Is this the kind of file that belongs where a bridge binary goes, on this platform? A correct
// digest over the wrong file would still be an installation that cannot run.
inline bool looks_like_executable(std::string_view data) {
    if (data.size() <= 100 * 1024) return false;
#ifdef _WIN32
    return data.starts_with("MZ");
#elif defined(__APPLE__)
    return data.starts_with("\xcf\xfa\xed\xfe") || data.starts_with("\xce\xfa\xed\xfe") || data.starts_with("\xca\xfe\xba\xbe");
#else
    return data.starts_with("\x7f" "ELF");
#endif
}

// Creates `path` with `text`, private, only if it does not exist: the one lock every platform
// has. Returns false when it already exists (or cannot be made).
inline bool create_exclusive(const std::filesystem::path& path, std::string_view text) {
#ifdef _WIN32
    HANDLE h = ::CreateFileW(path.c_str(), GENERIC_WRITE, 0, nullptr, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    ::WriteFile(h, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
    ::CloseHandle(h);
    restrict_to_owner(path, false);
    return true;
#else
    const int fd = ::open(path.c_str(), O_CREAT | O_EXCL | O_WRONLY, 0600);
    if (fd < 0) return false;
    [[maybe_unused]] auto n = ::write(fd, text.data(), text.size());
    ::close(fd);
    return true;
#endif
}

// A symbolic link, or on Windows also a junction or any other reparse point: something whose
// name may not lead where it appears to. The live renderer refuses to follow one.
inline bool is_reparse_point(const std::filesystem::path& path) {
    std::error_code ec;
    if (std::filesystem::is_symlink(path, ec)) return true;
#ifdef _WIN32
    const DWORD attributes = ::GetFileAttributesW(path.c_str());
    return attributes != INVALID_FILE_ATTRIBUTES && (attributes & FILE_ATTRIBUTE_REPARSE_POINT);
#else
    return false;
#endif
}

// Appends `text` to `path`, creating it private, and refuses a symbolic link at open time (Unix
// O_NOFOLLOW; on Windows the caller's reparse check stands in for it).
inline bool append_no_follow(const std::filesystem::path& path, std::string_view text) {
#ifdef _WIN32
    if (is_reparse_point(path)) return false;
    HANDLE h = ::CreateFileW(path.c_str(), FILE_APPEND_DATA, FILE_SHARE_READ, nullptr, OPEN_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (h == INVALID_HANDLE_VALUE) return false;
    DWORD written = 0;
    const BOOL ok = ::WriteFile(h, text.data(), static_cast<DWORD>(text.size()), &written, nullptr);
    ::CloseHandle(h);
    return ok;
#else
    const int fd = ::open(path.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_NOFOLLOW, 0600);
    if (fd < 0) return false;
    const auto n = ::write(fd, text.data(), text.size());
    ::close(fd);
    return n == static_cast<ssize_t>(text.size());
#endif
}

// Is this directory this user's own and nobody else's? On Unix that is a question about the
// owner and the mode, and both are asked. Windows has neither, and the directory in question is
// inside %LOCALAPPDATA%, which the platform already keeps per-user.
inline bool owned_private_dir(const std::filesystem::path& dir) {
    std::error_code ec;
    const auto status = std::filesystem::symlink_status(dir, ec);
    if (ec || !std::filesystem::is_directory(status)) return false;
#ifdef _WIN32
    return !is_reparse_point(dir);
#else
    struct stat st{};
    if (::lstat(dir.c_str(), &st) != 0 || !S_ISDIR(st.st_mode)) return false;
    return st.st_uid == ::getuid() && (st.st_mode & 077) == 0;
#endif
}

// One command line for the AI host to run, quoted the way that host's shell will read it.
//
// Claude Code runs a hook command through the platform shell, which on Windows is PowerShell,
// where a bare quoted path is a string expression and not a command: it needs the call
// operator. Codex is the same shape. Getting this wrong is silent on a path without spaces and
// breaks for every user whose name has one, which is most of them on Windows.
inline std::string quote_for_host(const std::vector<std::string>& parts) {
    std::string out;
#ifdef _WIN32
    out = "&";
    for (const auto& p : parts) {
        out += " \"";
        for (const char c : p) { if (c == '"') out += '`'; out += c; }
        out += '"';
    }
#else
    for (const auto& p : parts) {
        if (!out.empty()) out += ' ';
        out += '\'';
        for (const char c : p) { if (c == '\'') out += "'\\''"; else out += c; }
        out += '\'';
    }
#endif
    return out;
}

// Where a bridge that setup installs for the user goes. ~/.local/bin is a Unix convention with
// no Windows equivalent, so on Windows it lives beside the rest of CONVERGE's own state.
inline std::filesystem::path managed_bridge_path() {
#ifdef _WIN32
    return state_dir() / "bin" / "converge-bridge.exe";
#else
    return home() / ".local" / "bin" / "converge-bridge";
#endif
}

} // namespace converge::platform
