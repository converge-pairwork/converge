#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace converge::crypto {

using Bytes = std::vector<std::uint8_t>;
using Key32 = std::array<std::uint8_t, 32>;

std::string b64_encode(const std::uint8_t* p, std::size_t n);
std::optional<Bytes> b64_decode(std::string_view s);
std::string hex(const std::uint8_t* p, std::size_t n);
std::array<std::uint8_t, 32> sha256(std::string_view data);

// Ephemeral X25519 identity for one bridge process.
class Identity {
public:
    Identity();                                // fresh random key
    const Key32& pub() const { return pub_; }
    std::string pub_b64() const { return b64_encode(pub_.data(), pub_.size()); }
    Key32 shared_secret(const Key32& peer_pub) const;   // raw X25519
private:
    Key32 priv_{}, pub_{};
};

// Per-call session keys: one key per direction, derived via HKDF-SHA256.
//
// The shared secret supplies secrecy; the public keys and unique call context separate
// directions and calls. Call IDs must never be reused with the same process identity.
struct SessionKeys {
    Key32 send, recv;
};
SessionKeys derive_session(const Key32& shared, const Key32& my_pub, const Key32& peer_pub,
                           std::string_view call_id);

// ChaCha20-Poly1305 framing: [12 B nonce][ct || 16 B tag]. Nonce = dir(4) || counter(8).
class Sealer {
public:
    Sealer(SessionKeys keys, const Key32& my_pub, const Key32& peer_pub);
    Bytes seal(std::string_view plaintext);
    std::optional<std::string> open(const std::uint8_t* frame, std::size_t n);
private:
    SessionKeys k_;
    std::string aad_send_, aad_recv_;
    std::uint32_t dir_send_, dir_recv_;
    std::uint64_t ctr_send_ = 0;
    std::uint64_t ctr_recv_expected_ = 0;   // replay / reorder protection
};

// 6-digit short authentication string both sides display and compare out-of-band.
std::string sas(const Key32& pub_a, const Key32& pub_b);

} // namespace converge::crypto
