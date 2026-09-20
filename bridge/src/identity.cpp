#include "identity.hpp"

#include "crypto.hpp"

#include <openssl/evp.h>

#include "platform.hpp"

// The ssh-agent identity talks to $SSH_AUTH_SOCK over an AF_UNIX socket. That is the one thing
// in this file with no Windows equivalent worth writing: Windows OpenSSH's agent is a named
// pipe with a different protocol surface. Rather than pretend, the agent identity is simply not
// offered there, and says so; the file identity, which is what setup installs, works everywhere.
#ifndef _WIN32
#include <sys/socket.h>
#include <sys/un.h>
#include <unistd.h>
#endif

#include <cstdlib>
#include <cstring>
#include <format>
#include <fstream>
#include <filesystem>

namespace converge {

namespace {

struct PkeyDel { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct MdDel { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDel>;

void put_u32(std::vector<std::uint8_t>& v, std::uint32_t n) {
    for (int i = 3; i >= 0; --i) v.push_back(static_cast<std::uint8_t>(n >> (8 * i)));
}
void put_string(std::vector<std::uint8_t>& v, const void* p, std::size_t n) {
    put_u32(v, static_cast<std::uint32_t>(n));
    const auto* b = static_cast<const std::uint8_t*>(p);
    v.insert(v.end(), b, b + n);
}
std::optional<std::vector<std::uint8_t>> get_string(const std::vector<std::uint8_t>& b, std::size_t& off) {
    if (off + 4 > b.size()) return std::nullopt;
    const std::uint32_t n = static_cast<std::uint32_t>(b[off]) << 24 | static_cast<std::uint32_t>(b[off + 1]) << 16 |
                            static_cast<std::uint32_t>(b[off + 2]) << 8 | static_cast<std::uint32_t>(b[off + 3]);
    off += 4;
    if (off + n > b.size()) return std::nullopt;
    std::vector<std::uint8_t> out(b.begin() + static_cast<long>(off), b.begin() + static_cast<long>(off + n));
    off += n;
    return out;
}

std::vector<std::uint8_t> ed25519_blob(const std::array<std::uint8_t, 32>& raw) {
    std::vector<std::uint8_t> blob;
    put_string(blob, "ssh-ed25519", 11);
    put_string(blob, raw.data(), raw.size());
    return blob;
}

// ---------------------------------------------------------------- file signer
class FileSigner final : public Signer {
public:
    FileSigner(Pkey pk, std::string path) : pk_(std::move(pk)), path_(std::move(path)) {
        std::size_t n = raw_.size();
        EVP_PKEY_get_raw_public_key(pk_.get(), raw_.data(), &n);
        line_ = ssh_line_from_raw(raw_, "converge-bridge");
    }
    std::string public_ssh_line() const override { return line_; }
    std::string describe() const override { return "identity file " + path_; }
    std::optional<std::vector<std::uint8_t>> sign(std::string_view message) override {
        std::unique_ptr<EVP_MD_CTX, MdDel> ctx(EVP_MD_CTX_new());
        std::vector<std::uint8_t> sig(64);
        std::size_t len = sig.size();
        if (EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, pk_.get()) != 1) return std::nullopt;
        if (EVP_DigestSign(ctx.get(), sig.data(), &len,
                           reinterpret_cast<const unsigned char*>(message.data()), message.size()) != 1)
            return std::nullopt;
        sig.resize(len);
        return sig;
    }
private:
    Pkey pk_;
    std::string path_, line_;
    std::array<std::uint8_t, 32> raw_{};
};

// --------------------------------------------------------------- agent signer
// Minimal ssh-agent client (draft-miller-ssh-agent): length-prefixed messages over
// $SSH_AUTH_SOCK. We only need REQUEST_IDENTITIES and SIGN_REQUEST for ed25519.
#ifndef _WIN32
class AgentConn {
public:
    explicit AgentConn(const std::string& path) {
        fd_ = ::socket(AF_UNIX, SOCK_STREAM, 0);
        if (fd_ < 0) return;
        sockaddr_un addr{};
        addr.sun_family = AF_UNIX;
        std::strncpy(addr.sun_path, path.c_str(), sizeof(addr.sun_path) - 1);
        if (::connect(fd_, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0) { ::close(fd_); fd_ = -1; }
    }
    ~AgentConn() { if (fd_ >= 0) ::close(fd_); }
    bool ok() const { return fd_ >= 0; }

    std::optional<std::vector<std::uint8_t>> request(std::uint8_t type, const std::vector<std::uint8_t>& payload) {
        std::vector<std::uint8_t> msg;
        put_u32(msg, static_cast<std::uint32_t>(payload.size() + 1));
        msg.push_back(type);
        msg.insert(msg.end(), payload.begin(), payload.end());
        if (!write_all(msg.data(), msg.size())) return std::nullopt;
        std::uint8_t len[4];
        if (!read_all(len, 4)) return std::nullopt;
        const std::uint32_t n = static_cast<std::uint32_t>(len[0]) << 24 | static_cast<std::uint32_t>(len[1]) << 16 |
                                static_cast<std::uint32_t>(len[2]) << 8 | static_cast<std::uint32_t>(len[3]);
        if (n == 0 || n > 256 * 1024) return std::nullopt;
        std::vector<std::uint8_t> resp(n);
        if (!read_all(resp.data(), n)) return std::nullopt;
        return resp;
    }
private:
    bool write_all(const std::uint8_t* p, std::size_t n) {
        while (n) {
            auto w = ::write(fd_, p, n);
            if (w <= 0) return false;
            p += w; n -= static_cast<std::size_t>(w);
        }
        return true;
    }
    bool read_all(std::uint8_t* p, std::size_t n) {
        while (n) {
            auto r = ::read(fd_, p, n);
            if (r <= 0) return false;
            p += r; n -= static_cast<std::size_t>(r);
        }
        return true;
    }
    int fd_ = -1;
};

class AgentSigner final : public Signer {
public:
    AgentSigner(std::string sock, std::vector<std::uint8_t> blob, std::string line)
        : sock_(std::move(sock)), blob_(std::move(blob)), line_(std::move(line)) {}
    std::string public_ssh_line() const override { return line_; }
    std::string describe() const override { return "ssh-agent " + sock_; }
    std::optional<std::vector<std::uint8_t>> sign(std::string_view message) override {
        AgentConn c(sock_);
        if (!c.ok()) return std::nullopt;
        std::vector<std::uint8_t> req;
        put_string(req, blob_.data(), blob_.size());
        put_string(req, message.data(), message.size());
        put_u32(req, 0);                                  // flags
        auto resp = c.request(13 /* SSH_AGENTC_SIGN_REQUEST */, req);
        if (!resp || resp->empty() || (*resp)[0] != 14 /* SIGN_RESPONSE */) return std::nullopt;
        std::size_t off = 1;
        auto sigblob = get_string(*resp, off);
        if (!sigblob) return std::nullopt;
        std::size_t soff = 0;
        auto type = get_string(*sigblob, soff);
        auto sig = get_string(*sigblob, soff);
        if (!type || !sig || sig->size() != 64) return std::nullopt;
        return *sig;
    }
private:
    std::string sock_;
    std::vector<std::uint8_t> blob_;
    std::string line_;
};

#endif // !_WIN32

} // namespace

std::string default_identity_path() {
    return (platform::state_dir() / "identity").string();
}

std::unique_ptr<Signer> make_file_signer(const std::string& path, bool create, std::string* err) {
    namespace fs = std::filesystem;
    Pkey pk;
    std::error_code ec;
    if (fs::exists(path, ec)) {
        std::ifstream in(path);
        std::string b64((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        while (!b64.empty() && (b64.back() == '\n' || b64.back() == '\r' || b64.back() == ' ')) b64.pop_back();
        auto raw = crypto::b64_decode(b64);
        if (!raw || raw->size() != 32) { *err = "identity file is not a 32-byte ed25519 seed: " + path; return nullptr; }
        pk.reset(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, raw->data(), raw->size()));
        if (!pk) { *err = "cannot load identity from " + path; return nullptr; }
    } else {
        if (!create) { *err = "no identity file at " + path; return nullptr; }
        pk.reset(EVP_PKEY_Q_keygen(nullptr, nullptr, "ED25519"));
        if (!pk) { *err = "ed25519 keygen failed"; return nullptr; }
        std::array<std::uint8_t, 32> priv{};
        std::size_t n = priv.size();
        if (EVP_PKEY_get_raw_private_key(pk.get(), priv.data(), &n) != 1) { *err = "cannot export identity"; return nullptr; }
        // The directory first, private where the platform can say so, then the key inside it.
        platform::make_private_dir(fs::path(path).parent_path());
        std::ofstream out(path, std::ios::trunc);
        if (!out) { *err = "cannot write " + path; return nullptr; }
        out << crypto::b64_encode(priv.data(), priv.size()) << "\n";
        out.close();
        // Owner read/write only, in whatever terms this platform has for that: 0600 on Unix,
        // a protected one-entry ACL on Windows. See platform.hpp.
        platform::make_private_file(path);
    }
    return std::make_unique<FileSigner>(std::move(pk), path);
}

std::unique_ptr<Signer> make_agent_signer(const std::string& pubkey_filter, std::string* err) {
#ifdef _WIN32
    (void)pubkey_filter;
    *err = "an ssh-agent identity is not available on Windows; use --identity-file, which is what setup installs";
    return nullptr;
#else
    const char* sock = std::getenv("SSH_AUTH_SOCK");
    if (!sock || !*sock) { *err = "SSH_AUTH_SOCK is not set. Is ssh-agent running?"; return nullptr; }
    AgentConn c(sock);
    if (!c.ok()) { *err = std::string("cannot connect to ssh-agent at ") + sock; return nullptr; }
    auto resp = c.request(11 /* REQUEST_IDENTITIES */, {});
    if (!resp || resp->empty() || (*resp)[0] != 12 /* IDENTITIES_ANSWER */) {
        *err = "ssh-agent did not answer with an identity list";
        return nullptr;
    }
    std::size_t off = 1;
    if (off + 4 > resp->size()) { *err = "malformed agent reply"; return nullptr; }
    const std::uint32_t count = static_cast<std::uint32_t>((*resp)[off]) << 24 |
                                static_cast<std::uint32_t>((*resp)[off + 1]) << 16 |
                                static_cast<std::uint32_t>((*resp)[off + 2]) << 8 |
                                static_cast<std::uint32_t>((*resp)[off + 3]);
    off += 4;
    auto wanted = pubkey_filter.empty() ? std::optional<SshEd25519>{} : parse_ssh_ed25519(pubkey_filter);
    for (std::uint32_t i = 0; i < count; ++i) {
        auto blob = get_string(*resp, off);
        auto comment = get_string(*resp, off);
        if (!blob || !comment) break;
        std::size_t boff = 0;
        auto type = get_string(*blob, boff);
        auto key = get_string(*blob, boff);
        if (!type || !key || key->size() != 32) continue;
        if (std::string_view(reinterpret_cast<const char*>(type->data()), type->size()) != "ssh-ed25519") continue;
        std::array<std::uint8_t, 32> raw{};
        std::copy(key->begin(), key->end(), raw.begin());
        if (wanted && wanted->raw != raw) continue;
        return std::make_unique<AgentSigner>(sock, *blob,
                   ssh_line_from_raw(raw, std::string(comment->begin(), comment->end())));
    }
    *err = pubkey_filter.empty() ? "ssh-agent holds no ed25519 key" : "ssh-agent does not hold that key";
    return nullptr;
#endif
}

// --- helpers ---------------------------------------------------------------
std::string ssh_line_from_raw(const std::array<std::uint8_t, 32>& raw, std::string_view comment) {
    auto blob = ed25519_blob(raw);
    std::string line = "ssh-ed25519 " + crypto::b64_encode(blob.data(), blob.size());
    if (!comment.empty()) line += " " + std::string(comment);
    return line;
}

std::optional<SshEd25519> parse_ssh_ed25519(std::string_view line) {
    while (!line.empty() && (line.front() == ' ' || line.front() == '\t')) line.remove_prefix(1);
    while (!line.empty() && (line.back() == ' ' || line.back() == '\n' || line.back() == '\r')) line.remove_suffix(1);
    constexpr std::string_view kType = "ssh-ed25519";
    if (!line.starts_with(kType)) return std::nullopt;
    line.remove_prefix(kType.size());
    while (!line.empty() && line.front() == ' ') line.remove_prefix(1);
    const auto sp = line.find(' ');
    const auto blob_b64 = line.substr(0, sp);
    auto blob = crypto::b64_decode(blob_b64);
    if (!blob) return std::nullopt;
    std::size_t off = 0;
    auto type = get_string(*blob, off);
    auto key = get_string(*blob, off);
    if (!type || !key || key->size() != 32 || off != blob->size()) return std::nullopt;
    if (std::string_view(reinterpret_cast<const char*>(type->data()), type->size()) != kType) return std::nullopt;
    SshEd25519 out;
    std::copy(key->begin(), key->end(), out.raw.begin());
    out.canonical = std::string(kType) + " " + std::string(blob_b64);
    if (sp != std::string_view::npos) out.comment = std::string(line.substr(sp + 1));
    return out;
}

bool verify_ssh_ed25519(std::string_view canonical, std::string_view message,
                        const std::vector<std::uint8_t>& sig) {
    if (sig.size() != 64) return false;
    auto k = parse_ssh_ed25519(canonical);
    if (!k) return false;
    Pkey pk(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, k->raw.data(), k->raw.size()));
    if (!pk) return false;
    std::unique_ptr<EVP_MD_CTX, MdDel> ctx(EVP_MD_CTX_new());
    if (EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, pk.get()) != 1) return false;
    return EVP_DigestVerify(ctx.get(), sig.data(), sig.size(),
                            reinterpret_cast<const unsigned char*>(message.data()), message.size()) == 1;
}

std::string auth_challenge_message(std::string_view nonce, std::string_view handle) {
    return std::format("converge-auth-v1\n{}\n{}", handle, nonce);
}

std::string session_binding_message(std::string_view handle, std::string_view ephemeral_pub_b64) {
    return std::format("converge-session-v1\n{}\n{}", handle, ephemeral_pub_b64);
}

std::string commitment_message(std::string_view exchange_id, std::uint64_t round, std::string_view hash) {
    return std::format("converge-commit-v1\n{}\n{}\n{}", exchange_id, round, hash);
}

} // namespace converge
