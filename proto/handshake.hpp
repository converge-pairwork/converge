// The v4 handshake and the sealed stream it yields, for both ends of the link. Header only,
// OpenSSL 3 for the primitives: X25519, HKDF-SHA256, ChaCha20-Poly1305, Ed25519, SHA-256.
//
// Key schedule (README, "Handshake"):
//
//   ee   = X25519(client ephemeral, relay ephemeral)
//   ck1  = HKDF(salt "converge-v4", ikm ee, info "ck1")          the relay's static key is sealed under HKDF(ck1, "body")
//   es   = X25519(client ephemeral, relay static)
//   ck2  = HKDF(salt ck1, ikm es, info "ck2")                     only the holder of the static key reaches this
//   confirm tag = AEAD(HKDF(ck2, "confirm"), nonce 0, "", AD = SHA-256(m1 || relay ephemeral || sealed body))
//   h    = SHA-256("converge-v4-transcript" || m1 || m2)           m1, m2: the two frames exactly as sent
//   k_c2r = HKDF(ck2, "c2r" || h),  k_r2c = HKDF(ck2, "r2c" || h)  stream keys, one per direction
//
// A stream frame is AEAD(k_dir, nonce = dir(4) || counter(8) big endian, plaintext QSF frame, AD = h).
// Counters start at 0 with every handshake, and a frame out of order is refused: there is no
// window, because the carrier delivers in order.
//
// What identities sign (text, so a wallet can show it; a bridge signs the same bytes):
//
//   converge-v4-auth\n<domain>\n<identity base58>\n<h hex>\n<relay static key base58>
//   converge-session-v4\n<identity base58>\n<call key base58>
//
// A certificate body (converge-member-v1) and its off-chain wrapper are in certificate.hpp.
#pragma once

#include "base58.hpp"
#include "link.hpp"
#include "qsf.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <array>
#include <cstring>
#include <expected>
#include <functional>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace converge::link {

using bytes = std::vector<std::uint8_t>;

enum class hs_error : std::uint8_t {
    malformed,          // a frame that does not decode
    version,            // the other side speaks another protocol
    crypto,             // a primitive failed (never expected)
    static_key,         // the relay's static key is not the one expected
    confirm,            // the relay could not prove it holds its static key
    sealed,             // a sealed frame did not open (wrong key, tampered, or out of order)
    order,              // a handshake step out of sequence
};
template <class T> using hs_result = std::expected<T, hs_error>;

// ---- primitives ------------------------------------------------------------------------------------------
namespace crypto {

struct PkeyDeleter { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct CtxDeleter { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct MdDeleter { void operator()(EVP_MD_CTX* p) const { EVP_MD_CTX_free(p); } };
struct CipherDeleter { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDeleter>;
using Pctx = std::unique_ptr<EVP_PKEY_CTX, CtxDeleter>;

inline bool random_bytes(std::uint8_t* p, std::size_t n) { return RAND_bytes(p, static_cast<int>(n)) == 1; }
template <std::size_t N> std::array<std::uint8_t, N> random_array() { std::array<std::uint8_t, N> a{}; random_bytes(a.data(), N); return a; }

inline key32 sha256(const std::uint8_t* p, std::size_t n) { key32 out{}; SHA256(p, n, out.data()); return out; }
inline key32 sha256(std::string_view s) { return sha256(reinterpret_cast<const std::uint8_t*>(s.data()), s.size()); }

inline std::string hex(const std::uint8_t* p, std::size_t n) {
    static constexpr char d[] = "0123456789abcdef";
    std::string out; out.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { out.push_back(d[p[i] >> 4]); out.push_back(d[p[i] & 15]); }
    return out;
}

inline std::optional<key32> hkdf32(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm, std::span<const std::uint8_t> info) {
    Pctx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    key32 out{}; std::size_t n = out.size();
    if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 || EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), salt.data(), static_cast<int>(salt.size())) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), ikm.data(), static_cast<int>(ikm.size())) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), static_cast<int>(info.size())) != 1 ||
        EVP_PKEY_derive(ctx.get(), out.data(), &n) != 1 || n != 32)
        return std::nullopt;
    return out;
}
inline std::optional<key32> hkdf32(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm, std::string_view info) {
    return hkdf32(salt, ikm, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(info.data()), info.size()));
}

// X25519
struct X25519 {
    key32 priv{}, pub{};
    static std::optional<X25519> generate() {
        Pctx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr));
        EVP_PKEY* raw = nullptr;
        if (!ctx || EVP_PKEY_keygen_init(ctx.get()) != 1 || EVP_PKEY_keygen(ctx.get(), &raw) != 1) return std::nullopt;
        Pkey key(raw);
        X25519 k; std::size_t n = 32;
        if (EVP_PKEY_get_raw_private_key(key.get(), k.priv.data(), &n) != 1 || n != 32) return std::nullopt;
        n = 32;
        if (EVP_PKEY_get_raw_public_key(key.get(), k.pub.data(), &n) != 1 || n != 32) return std::nullopt;
        return k;
    }
    static std::optional<X25519> from_private(const key32& priv) {
        Pkey key(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size()));
        if (!key) return std::nullopt;
        X25519 k; k.priv = priv; std::size_t n = 32;
        if (EVP_PKEY_get_raw_public_key(key.get(), k.pub.data(), &n) != 1 || n != 32) return std::nullopt;
        return k;
    }
    std::optional<key32> shared(const key32& peer_pub) const {
        Pkey me(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv.data(), priv.size()));
        Pkey peer(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), peer_pub.size()));
        if (!me || !peer) return std::nullopt;
        Pctx ctx(EVP_PKEY_CTX_new(me.get(), nullptr));
        key32 out{}; std::size_t n = 32;
        if (!ctx || EVP_PKEY_derive_init(ctx.get()) != 1 || EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1 ||
            EVP_PKEY_derive(ctx.get(), out.data(), &n) != 1 || n != 32)
            return std::nullopt;
        return out;
    }
};

// ChaCha20-Poly1305, nonce = dir(4) || counter(8), big endian.
inline std::array<std::uint8_t, 12> nonce_of(std::uint32_t dir, std::uint64_t counter) {
    std::array<std::uint8_t, 12> n{};
    for (int i = 0; i < 4; ++i) n[i] = static_cast<std::uint8_t>(dir >> (24 - 8 * i));
    for (int i = 0; i < 8; ++i) n[4 + i] = static_cast<std::uint8_t>(counter >> (56 - 8 * i));
    return n;
}
inline std::optional<bytes> aead_seal(const key32& key, const std::array<std::uint8_t, 12>& nonce, std::span<const std::uint8_t> plaintext,
                                      std::span<const std::uint8_t> ad) {
    std::unique_ptr<EVP_CIPHER_CTX, CipherDeleter> ctx(EVP_CIPHER_CTX_new());
    bytes out(plaintext.size() + 16);
    int len = 0, total = 0;
    if (!ctx || EVP_EncryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) != 1) return std::nullopt;
    if (!ad.empty() && EVP_EncryptUpdate(ctx.get(), nullptr, &len, ad.data(), static_cast<int>(ad.size())) != 1) return std::nullopt;
    if (!plaintext.empty() && EVP_EncryptUpdate(ctx.get(), out.data(), &len, plaintext.data(), static_cast<int>(plaintext.size())) != 1) return std::nullopt;
    total = len;
    if (EVP_EncryptFinal_ex(ctx.get(), out.data() + total, &len) != 1) return std::nullopt;
    total += len;
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_GET_TAG, 16, out.data() + plaintext.size()) != 1) return std::nullopt;
    out.resize(plaintext.size() + 16);
    return out;
}
inline std::optional<bytes> aead_open(const key32& key, const std::array<std::uint8_t, 12>& nonce, std::span<const std::uint8_t> sealed,
                                      std::span<const std::uint8_t> ad) {
    if (sealed.size() < 16) return std::nullopt;
    std::unique_ptr<EVP_CIPHER_CTX, CipherDeleter> ctx(EVP_CIPHER_CTX_new());
    const std::size_t ct = sealed.size() - 16;
    bytes out(ct);
    int len = 0, total = 0;
    if (!ctx || EVP_DecryptInit_ex(ctx.get(), EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) != 1) return std::nullopt;
    if (!ad.empty() && EVP_DecryptUpdate(ctx.get(), nullptr, &len, ad.data(), static_cast<int>(ad.size())) != 1) return std::nullopt;
    if (ct && EVP_DecryptUpdate(ctx.get(), out.data(), &len, sealed.data(), static_cast<int>(ct)) != 1) return std::nullopt;
    total = len;
    std::array<std::uint8_t, 16> tag{};
    std::memcpy(tag.data(), sealed.data() + ct, 16);
    if (EVP_CIPHER_CTX_ctrl(ctx.get(), EVP_CTRL_AEAD_SET_TAG, 16, tag.data()) != 1) return std::nullopt;
    if (EVP_DecryptFinal_ex(ctx.get(), out.data() + total, &len) != 1) return std::nullopt;
    out.resize(static_cast<std::size_t>(total + len));
    return out;
}

// Ed25519
inline std::optional<key32> ed25519_public(const key32& seed) {
    Pkey key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()));
    if (!key) return std::nullopt;
    key32 pub{}; std::size_t n = 32;
    if (EVP_PKEY_get_raw_public_key(key.get(), pub.data(), &n) != 1 || n != 32) return std::nullopt;
    return pub;
}
inline std::optional<sig64> ed25519_sign(const key32& seed, std::span<const std::uint8_t> message) {
    Pkey key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), seed.size()));
    std::unique_ptr<EVP_MD_CTX, MdDeleter> ctx(EVP_MD_CTX_new());
    sig64 sig{}; std::size_t n = sig.size();
    if (!key || !ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) != 1 ||
        EVP_DigestSign(ctx.get(), sig.data(), &n, message.data(), message.size()) != 1 || n != 64)
        return std::nullopt;
    return sig;
}
inline std::optional<sig64> ed25519_sign(const key32& seed, std::string_view message) {
    return ed25519_sign(seed, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
}
inline bool ed25519_verify(const key32& pub, std::span<const std::uint8_t> message, const sig64& sig) {
    Pkey key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, pub.data(), pub.size()));
    std::unique_ptr<EVP_MD_CTX, MdDeleter> ctx(EVP_MD_CTX_new());
    return key && ctx && EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1 &&
           EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), message.data(), message.size()) == 1;
}
inline bool ed25519_verify(const key32& pub, std::string_view message, const sig64& sig) {
    return ed25519_verify(pub, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()), sig);
}

} // namespace crypto

// ---- names and texts --------------------------------------------------------------------------------------
inline std::string identity_text(const key32& identity) { return base58::encode(identity.data(), identity.size()); }
inline std::optional<key32> identity_from_text(std::string_view b58) {
    auto v = base58::decode(b58);
    if (v.size() != 32) return std::nullopt;
    key32 k{}; std::copy(v.begin(), v.end(), k.begin());
    return k;
}
// A handle is a name for a key, derived from it: cvh_ + 12 hex of SHA-256(identity).
inline std::string handle_of(const key32& identity) {
    const auto h = crypto::sha256(identity.data(), identity.size());
    return "cvh_" + crypto::hex(h.data(), 6);
}
inline std::string auth_text(std::string_view domain, const key32& identity, const key32& transcript, const key32& relay_static) {
    return "converge-v4-auth\n" + std::string(domain) + "\n" + identity_text(identity) + "\n" + crypto::hex(transcript.data(), transcript.size()) +
           "\n" + base58::encode(relay_static.data(), relay_static.size());
}
inline std::string call_key_binding_text(const key32& identity, const key32& call_key) {
    return "converge-session-v4\n" + identity_text(identity) + "\n" + base58::encode(call_key.data(), call_key.size());
}
// v3's commitment and receipt texts, unchanged: the barrier is the same protocol.
inline std::string commit_text(std::string_view exchange_id, std::uint64_t round, std::string_view hash) {
    return "converge-commit-v1\n" + std::string(exchange_id) + "\n" + std::to_string(round) + "\n" + std::string(hash);
}
inline std::string receipt_text(const receipt& x) {
    return "converge-receipt-v1\n" + x.call_id + "\n" + x.exchange_id + "\n" + x.phase + "\n" + std::to_string(x.round) + "\n" + x.commit_a + "\n" +
           x.commit_b + "\n" + std::to_string(x.ts);
}

// ---- the sealed stream ------------------------------------------------------------------------------------
class channel {
public:
    channel() = default;
    channel(key32 send_key, key32 recv_key, std::uint32_t send_dir, key32 transcript)
        : send_(send_key), recv_(recv_key), send_dir_(send_dir), recv_dir_(1 - send_dir), h_(transcript), ready_(true) {}
    bool ready() const { return ready_; }
    const key32& transcript() const { return h_; }
    std::optional<bytes> seal(std::span<const std::uint8_t> frame) {
        auto out = crypto::aead_seal(send_, crypto::nonce_of(send_dir_, send_ctr_), frame, h_);
        if (out) ++send_ctr_;
        return out;
    }
    hs_result<bytes> open(std::span<const std::uint8_t> sealed) {
        auto out = crypto::aead_open(recv_, crypto::nonce_of(recv_dir_, recv_ctr_), sealed, h_);
        if (!out) return std::unexpected(hs_error::sealed);
        ++recv_ctr_;
        return *out;
    }
    std::uint64_t sent() const { return send_ctr_; }
    std::uint64_t received() const { return recv_ctr_; }
private:
    key32 send_{}, recv_{};
    std::uint32_t send_dir_ = 0, recv_dir_ = 1;
    key32 h_{};
    std::uint64_t send_ctr_ = 0, recv_ctr_ = 0;
    bool ready_ = false;
};

namespace detail {
inline constexpr std::uint32_t dir_c2r = 0, dir_r2c = 1;
inline constexpr std::string_view salt = "converge-v4";
inline std::span<const std::uint8_t> sp(std::string_view s) { return {reinterpret_cast<const std::uint8_t*>(s.data()), s.size()}; }
inline std::span<const std::uint8_t> sp(const key32& k) { return {k.data(), k.size()}; }
struct schedule {
    key32 ck1{}, ck2{}, h{};
    static std::optional<key32> body_key(const key32& ck1) { return crypto::hkdf32(sp(ck1), sp(ck1), "body"); }
    static std::optional<key32> confirm_key(const key32& ck2) { return crypto::hkdf32(sp(ck2), sp(ck2), "confirm"); }
    static std::optional<key32> stream_key(const key32& ck2, std::string_view dir, const key32& h) {
        bytes info(dir.begin(), dir.end()); info.insert(info.end(), h.begin(), h.end());
        return crypto::hkdf32(sp(ck2), sp(ck2), std::span<const std::uint8_t>(info));
    }
    static key32 confirm_ad(const qsf::blob& m1, const key32& re, const qsf::blob& sealed_body) {
        bytes all(m1.begin(), m1.end()); all.insert(all.end(), re.begin(), re.end()); all.insert(all.end(), sealed_body.begin(), sealed_body.end());
        return crypto::sha256(all.data(), all.size());
    }
    static key32 transcript(const qsf::blob& m1, const qsf::blob& m2) {
        bytes all(sp("converge-v4-transcript").begin(), sp("converge-v4-transcript").end());
        all.insert(all.end(), m1.begin(), m1.end()); all.insert(all.end(), m2.begin(), m2.end());
        return crypto::sha256(all.data(), all.size());
    }
};
} // namespace detail

// ---- the client side --------------------------------------------------------------------------------------
class initiator {
public:
    // `expected_static`: the relay key the client knows (pinned or published); nullopt = trust on
    // first use, and the caller pins what `relay_static()` returns.
    explicit initiator(std::optional<key32> expected_static = std::nullopt) : expected_(expected_static) {}
    hs_result<qsf::blob> hello(std::vector<std::string> features, carrier via = carrier::websocket) {
        auto e = crypto::X25519::generate();
        if (!e) return std::unexpected(hs_error::crypto);
        e_ = *e;
        client_hello m; m.ephemeral = e_.pub; m.nonce = crypto::random_array<16>(); m.features = std::move(features); m.via = via;
        m1_ = m.encode();
        state_ = 1;
        return m1_;
    }
    // Consumes the relay's hello. On success the channel is ready and `relay()` describes the relay.
    hs_result<relay_hello_body> on_relay_hello(std::span<const std::uint8_t> frame) {
        if (state_ != 1) return std::unexpected(hs_error::order);
        auto m = relay_hello::decode(frame);
        if (!m) return std::unexpected(hs_error::malformed);
        auto ee = e_.shared(m->ephemeral);
        if (!ee) return std::unexpected(hs_error::crypto);
        auto ck1 = crypto::hkdf32(detail::sp(detail::salt), detail::sp(*ee), "ck1");
        auto kb = ck1 ? detail::schedule::body_key(*ck1) : std::nullopt;
        if (!ck1 || !kb) return std::unexpected(hs_error::crypto);
        const auto ad = detail::schedule::confirm_ad(m1_, m->ephemeral, {});   // body is sealed with AD = SHA-256(m1 || re)
        auto body_plain = crypto::aead_open(*kb, crypto::nonce_of(detail::dir_r2c, 0), m->sealed_body, ad);
        if (!body_plain) return std::unexpected(hs_error::sealed);
        auto body = relay_hello_body::decode(*body_plain);
        if (!body) return std::unexpected(hs_error::malformed);
        if (body->protocol != protocol_version) return std::unexpected(hs_error::version);
        if (expected_ && *expected_ != body->static_key) return std::unexpected(hs_error::static_key);
        auto es = e_.shared(body->static_key);
        auto ck2 = es ? crypto::hkdf32(detail::sp(*ck1), detail::sp(*es), "ck2") : std::nullopt;
        auto kc = ck2 ? detail::schedule::confirm_key(*ck2) : std::nullopt;
        if (!es || !ck2 || !kc) return std::unexpected(hs_error::crypto);
        const auto cad = detail::schedule::confirm_ad(m1_, m->ephemeral, m->sealed_body);
        if (!crypto::aead_open(*kc, crypto::nonce_of(detail::dir_r2c, 0), m->confirm, cad)) return std::unexpected(hs_error::confirm);
        const qsf::blob m2(frame.begin(), frame.end());
        const auto h = detail::schedule::transcript(m1_, m2);
        auto kc2r = detail::schedule::stream_key(*ck2, "c2r", h), kr2c = detail::schedule::stream_key(*ck2, "r2c", h);
        if (!kc2r || !kr2c) return std::unexpected(hs_error::crypto);
        channel_ = channel(*kc2r, *kr2c, detail::dir_c2r, h);
        relay_ = *body;
        state_ = 2;
        return *body;
    }
    channel& stream() { return channel_; }
    const relay_hello_body& relay() const { return relay_; }
    const key32& relay_static() const { return relay_.static_key; }
    const key32& transcript() const { return channel_.transcript(); }
private:
    std::optional<key32> expected_;
    crypto::X25519 e_{};
    qsf::blob m1_;
    relay_hello_body relay_;
    channel channel_;
    int state_ = 0;
};

// ---- the relay side ---------------------------------------------------------------------------------------
class responder {
public:
    responder(crypto::X25519 static_key, std::string domain, std::vector<std::string> features)
        : s_(static_key), domain_(std::move(domain)), features_(std::move(features)) {}
    // Consumes the client's hello, produces the relay's. On success the channel is ready.
    hs_result<qsf::blob> on_client_hello(std::span<const std::uint8_t> frame) {
        if (state_ != 0) return std::unexpected(hs_error::order);
        auto m = client_hello::decode(frame);
        if (!m) return std::unexpected(hs_error::malformed);
        if (m->protocol != protocol_version) return std::unexpected(hs_error::version);
        client_ = *m;
        const qsf::blob m1(frame.begin(), frame.end());
        auto e = crypto::X25519::generate();
        if (!e) return std::unexpected(hs_error::crypto);
        auto ee = e->shared(m->ephemeral);
        auto ck1 = ee ? crypto::hkdf32(detail::sp(detail::salt), detail::sp(*ee), "ck1") : std::nullopt;
        auto kb = ck1 ? detail::schedule::body_key(*ck1) : std::nullopt;
        if (!ee || !ck1 || !kb) return std::unexpected(hs_error::crypto);
        relay_hello_body body; body.static_key = s_.pub; body.nonce = crypto::random_array<16>(); body.features = features_; body.domain = domain_;
        const auto plain = body.encode();
        auto sealed = crypto::aead_seal(*kb, crypto::nonce_of(detail::dir_r2c, 0), plain, detail::schedule::confirm_ad(m1, e->pub, {}));
        auto es = s_.shared(m->ephemeral);
        auto ck2 = es ? crypto::hkdf32(detail::sp(*ck1), detail::sp(*es), "ck2") : std::nullopt;
        auto kc = ck2 ? detail::schedule::confirm_key(*ck2) : std::nullopt;
        if (!sealed || !es || !ck2 || !kc) return std::unexpected(hs_error::crypto);
        auto confirm = crypto::aead_seal(*kc, crypto::nonce_of(detail::dir_r2c, 0), {}, detail::schedule::confirm_ad(m1, e->pub, *sealed));
        if (!confirm || confirm->size() != 16) return std::unexpected(hs_error::crypto);
        relay_hello out; out.ephemeral = e->pub; out.sealed_body = *sealed; std::copy(confirm->begin(), confirm->end(), out.confirm.begin());
        const auto m2 = out.encode();
        const auto h = detail::schedule::transcript(m1, m2);
        auto kc2r = detail::schedule::stream_key(*ck2, "c2r", h), kr2c = detail::schedule::stream_key(*ck2, "r2c", h);
        if (!kc2r || !kr2c) return std::unexpected(hs_error::crypto);
        channel_ = channel(*kr2c, *kc2r, detail::dir_r2c, h);
        state_ = 1;
        return m2;
    }
    channel& stream() { return channel_; }
    const client_hello& client() const { return client_; }
    const key32& transcript() const { return channel_.transcript(); }
    const key32& static_public() const { return s_.pub; }
private:
    crypto::X25519 s_;
    std::string domain_;
    std::vector<std::string> features_;
    client_hello client_;
    channel channel_;
    int state_ = 0;
};

// Verifies what client_auth claims, given the transcript: the identity signed this handshake for
// this relay, and the call key belongs to the identity. Certificates are the relay's business
// (certificate.hpp); this is the part both ends can check.
inline bool verify_client_auth(const client_auth& a, std::string_view domain, const key32& transcript, const key32& relay_static) {
    return crypto::ed25519_verify(a.identity, auth_text(domain, a.identity, transcript, relay_static), a.signature) &&
           crypto::ed25519_verify(a.identity, call_key_binding_text(a.identity, a.call_key), a.call_key_signature);
}

} // namespace converge::link
