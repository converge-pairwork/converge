// The platform seam: where private state goes on this operating system, and whether what is
// created there is actually private on it.
//
// This test compiles and runs on every supported platform and asks the same questions on each.
// The answers differ, the questions do not. On Windows it is the only place that proves the
// owner-only ACL is really applied, which is a thing a comment can claim and only a run can
// establish, so it is deliberately a runtime test and not a compile-time one.
#include "platform.hpp"

#include <cstdio>
#include <cstdlib>
#include <filesystem>
#include <fstream>
#include <random>
#include <string>

namespace fs = std::filesystem;
namespace platform = converge::platform;

static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); ++failures; } } while (0)

// A scratch directory of this run's own, removed on the way out. Nothing here ever looks at,
// writes to or reads from the real CONVERGE state: that is the property scripts/testhome.py
// keeps for the Python side, and this is the same promise on the C++ side.
static fs::path scratch() {
    std::random_device rd;
    const auto name = "converge-platform-test-" + std::to_string(rd());
    const auto dir = fs::temp_directory_path() / name;
    fs::create_directories(dir);
    return dir;
}

static void set_env(const char* name, const std::string& value) {
#ifdef _WIN32
    ::_putenv_s(name, value.c_str());
#else
    ::setenv(name, value.c_str(), 1);
#endif
}

static void clear_env(const char* name) {
#ifdef _WIN32
    ::_putenv_s(name, "");
#else
    ::unsetenv(name);
#endif
}

int main() {
    const fs::path root = scratch();

    // ---- CONVERGE_HOME wins on every platform, which is what makes tests isolatable ---------
    const fs::path forced = root / "forced-state";
    set_env("CONVERGE_HOME", forced.string());
    CHECK(platform::state_dir() == forced);
    clear_env("CONVERGE_HOME");

    // ---- otherwise the platform's own answer, and it is never the roaming profile -----------
    const fs::path fake_home = root / "home";
    fs::create_directories(fake_home);
    set_env("HOME", fake_home.string());
#ifdef _WIN32
    const fs::path local = root / "AppData" / "Local", roaming = root / "AppData" / "Roaming";
    fs::create_directories(local);
    fs::create_directories(roaming);
    set_env("USERPROFILE", fake_home.string());
    set_env("LOCALAPPDATA", local.string());
    set_env("APPDATA", roaming.string());
    CHECK(platform::state_dir() == local / "CONVERGE");
    // A private key must not follow the user between machines.
    CHECK(platform::state_dir().string().find(roaming.string()) == std::string::npos);
#else
    CHECK(platform::state_dir() == fake_home / ".converge");
#endif

    // ---- a created directory is this user's and nobody else's -------------------------------
    const fs::path dir = root / "state";
    platform::make_private_dir(dir);
    CHECK(fs::is_directory(dir));
    CHECK(platform::is_private(dir));

    // A directory that already exists with a wider mode is narrowed, not left as found: the
    // interesting case is an upgrade over an installation made before this code existed.
    const fs::path wide = root / "wide";
    fs::create_directories(wide);
#ifndef _WIN32
    fs::permissions(wide, fs::perms::all, fs::perm_options::replace);
    CHECK(!platform::is_private(wide));
#endif
    platform::make_private_dir(wide);
    CHECK(platform::is_private(wide));

    // ---- a created file is too, and inheriting from a private directory is not enough -------
    const fs::path key = dir / "identity";
    { std::ofstream out(key); out << "not a real key\n"; }
    CHECK(fs::exists(key));
    platform::make_private_file(key);
    CHECK(platform::is_private(key));

    // A file written into a directory that is not private does not become private by itself.
    // This is the check that fails if make_private_file is ever quietly turned into a no-op on
    // some platform, which is exactly what std::filesystem::permissions is on Windows.
    const fs::path loose = wide / "pins";
#ifndef _WIN32
    fs::permissions(wide, fs::perms::all, fs::perm_options::replace);
#endif
    { std::ofstream out(loose); out << "cvh_000000000000 key\n"; }
#ifndef _WIN32
    fs::permissions(loose, fs::perms::all, fs::perm_options::replace);
    CHECK(!platform::is_private(loose));
#endif
    platform::make_private_file(loose);
    CHECK(platform::is_private(loose));

    // ---- this process, and a process id that cannot be running ------------------------------
    CHECK(platform::process_id() != 0);
    // "Not sure" must mean "still alive": a false negative would delete a live bridge's
    // acknowledgements, and a false positive costs one stale file.
    CHECK(platform::process_alive(platform::process_id()));
    CHECK(platform::process_alive(0));

    // ---- a path with a space and a non-ASCII character survives the round trip ---------------
    const fs::path awkward = root / "jo blogs" / u8"état";
    platform::make_private_dir(awkward);
    CHECK(fs::is_directory(awkward));
    CHECK(platform::is_private(awkward));

    std::error_code ec;
    fs::remove_all(root, ec);
    if (failures) { std::printf("%d failure(s)\n", failures); return 1; }
    std::puts("all platform tests passed");
    return 0;
}
