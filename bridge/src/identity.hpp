#pragma once
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace converge {

// A long-lived Ed25519 identity for one member. Two backends:
//   * a dedicated key file the bridge generates on first run (default), and
//   * ssh-agent, so hardware-backed keys (YubiKey via ssh-sk) can be used.
//
// This is deliberately NOT the user's ~/.ssh identity: signing the relay's handshake with the
// key that also authorises git push and production SSH crosses trust domains. Point
// --identity-file at an existing key only if you mean to.
class Signer {
public:
    virtual ~Signer() = default;
    virtual std::string public_ssh_line() const = 0;      // "ssh-ed25519 AAAA... comment"
    virtual std::optional<std::vector<std::uint8_t>> sign(std::string_view message) = 0;
    virtual std::string describe() const = 0;
};

// Loads the key at `path`, creating it (0600) if absent and `create` is set.
std::unique_ptr<Signer> make_file_signer(const std::string& path, bool create, std::string* err);
// Uses $SSH_AUTH_SOCK. If `pubkey_filter` is set, picks that key, else the first ed25519.
std::unique_ptr<Signer> make_agent_signer(const std::string& pubkey_filter, std::string* err);

std::string default_identity_path();

// --- OpenSSH ed25519 helpers (also used to verify a peer's identity) ---------
struct SshEd25519 {
    std::string canonical;                 // "ssh-ed25519 <base64 blob>"
    std::array<std::uint8_t, 32> raw{};
    std::string comment;
};
std::optional<SshEd25519> parse_ssh_ed25519(std::string_view line);
std::string ssh_line_from_raw(const std::array<std::uint8_t, 32>& raw, std::string_view comment);
bool verify_ssh_ed25519(std::string_view canonical, std::string_view message,
                        const std::vector<std::uint8_t>& sig);

// The bytes a party signs to bind itself to an exchange commitment. Part of the wire protocol,
// so the peer constructs the same string and any change here is a protocol change. (The relay
// handshake's signed texts live in proto/handshake.hpp.)
std::string commitment_message(std::string_view exchange_id, std::uint64_t round, std::string_view hash);

} // namespace converge
