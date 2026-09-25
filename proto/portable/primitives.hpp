// The link's primitives in portable C++, with no dependency, so that every end of the link
// (the relay, the bridge and the web application compiled to WebAssembly) runs one
// implementation: X25519 and Ed25519 from TweetNaCl (public domain, tweetnacl.c beside this
// file, compiled once as nacl.cpp), ChaCha20-Poly1305 (RFC 8439), SHA-256 (FIPS 180-4), HMAC and
// HKDF (RFC 5869). tests/test_proto.cpp checks each against OpenSSL on random inputs and on the
// published vectors; nothing here is used for anything OpenSSL is not also asked about there.
#pragma once

#include <array>
#include <cstdint>
#include <cstring>
#include <optional>
#include <span>
#include <string_view>
#include <vector>

extern "C" {
int crypto_scalarmult_curve25519_tweet(unsigned char*, const unsigned char*, const unsigned char*);
int crypto_scalarmult_curve25519_tweet_base(unsigned char*, const unsigned char*);
int crypto_sign_ed25519_tweet(unsigned char*, unsigned long long*, const unsigned char*, unsigned long long, const unsigned char*);
int crypto_sign_ed25519_tweet_open(unsigned char*, unsigned long long*, const unsigned char*, unsigned long long, const unsigned char*);
int crypto_sign_ed25519_tweet_keypair(unsigned char*, unsigned char*);
int crypto_hash_sha512_tweet(unsigned char*, const unsigned char*, unsigned long long);
void randombytes(unsigned char*, unsigned long long);
int converge_ed25519_public_from_seed(unsigned char* pk, const unsigned char* seed);
}

namespace converge::link::portable {

using key32 = std::array<std::uint8_t, 32>;
using sig64 = std::array<std::uint8_t, 64>;
using bytes = std::vector<std::uint8_t>;

inline void random_bytes(std::uint8_t* p, std::size_t n) { randombytes(p, n); }

// ---- SHA-256 ----------------------------------------------------------------------------------------------
class sha256 {
public:
    sha256() { reset(); }
    void reset() {
        h_ = {0x6a09e667u, 0xbb67ae85u, 0x3c6ef372u, 0xa54ff53au, 0x510e527fu, 0x9b05688cu, 0x1f83d9abu, 0x5be0cd19u};
        len_ = 0; fill_ = 0;
    }
    void update(const std::uint8_t* p, std::size_t n) {
        len_ += n;
        while (n) {
            const std::size_t take = std::min(n, 64 - fill_);
            std::memcpy(buf_ + fill_, p, take);
            fill_ += take; p += take; n -= take;
            if (fill_ == 64) { block(buf_); fill_ = 0; }
        }
    }
    void update(std::string_view s) { update(reinterpret_cast<const std::uint8_t*>(s.data()), s.size()); }
    key32 finish() {
        const std::uint64_t bits = len_ * 8;
        std::uint8_t pad = 0x80;
        update(&pad, 1);
        std::uint8_t zero = 0;
        while (fill_ != 56) update(&zero, 1);
        std::uint8_t len[8];
        for (int i = 0; i < 8; ++i) len[i] = static_cast<std::uint8_t>(bits >> (56 - 8 * i));
        update(len, 8);
        key32 out{};
        for (int i = 0; i < 8; ++i) for (int j = 0; j < 4; ++j) out[static_cast<std::size_t>(i * 4 + j)] = static_cast<std::uint8_t>(h_[static_cast<std::size_t>(i)] >> (24 - 8 * j));
        return out;
    }
    static key32 of(const std::uint8_t* p, std::size_t n) { sha256 s; s.update(p, n); return s.finish(); }
    static key32 of(std::string_view s) { return of(reinterpret_cast<const std::uint8_t*>(s.data()), s.size()); }
private:
    static std::uint32_t rotr(std::uint32_t x, int n) { return (x >> n) | (x << (32 - n)); }
    void block(const std::uint8_t* p) {
        static constexpr std::uint32_t k[64] = {
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
            0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
            0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
            0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
            0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3, 0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2};
        std::uint32_t w[64];
        for (int i = 0; i < 16; ++i)
            w[i] = (std::uint32_t(p[i * 4]) << 24) | (std::uint32_t(p[i * 4 + 1]) << 16) | (std::uint32_t(p[i * 4 + 2]) << 8) | std::uint32_t(p[i * 4 + 3]);
        for (int i = 16; i < 64; ++i) {
            const auto s0 = rotr(w[i - 15], 7) ^ rotr(w[i - 15], 18) ^ (w[i - 15] >> 3);
            const auto s1 = rotr(w[i - 2], 17) ^ rotr(w[i - 2], 19) ^ (w[i - 2] >> 10);
            w[i] = w[i - 16] + s0 + w[i - 7] + s1;
        }
        std::uint32_t a = h_[0], b = h_[1], c = h_[2], d = h_[3], e = h_[4], f = h_[5], g = h_[6], h = h_[7];
        for (int i = 0; i < 64; ++i) {
            const auto S1 = rotr(e, 6) ^ rotr(e, 11) ^ rotr(e, 25);
            const auto ch = (e & f) ^ (~e & g);
            const auto t1 = h + S1 + ch + k[i] + w[i];
            const auto S0 = rotr(a, 2) ^ rotr(a, 13) ^ rotr(a, 22);
            const auto maj = (a & b) ^ (a & c) ^ (b & c);
            const auto t2 = S0 + maj;
            h = g; g = f; f = e; e = d + t1; d = c; c = b; b = a; a = t1 + t2;
        }
        h_[0] += a; h_[1] += b; h_[2] += c; h_[3] += d; h_[4] += e; h_[5] += f; h_[6] += g; h_[7] += h;
    }
    std::array<std::uint32_t, 8> h_{};
    std::uint8_t buf_[64]{};
    std::uint64_t len_ = 0;
    std::size_t fill_ = 0;
};

// ---- HMAC-SHA256 and HKDF (RFC 5869) --------------------------------------------------------------------------
inline key32 hmac_sha256(std::span<const std::uint8_t> key, std::span<const std::uint8_t> msg) {
    std::uint8_t k[64]{};
    if (key.size() > 64) { const auto h = sha256::of(key.data(), key.size()); std::memcpy(k, h.data(), 32); }
    else std::memcpy(k, key.data(), key.size());
    std::uint8_t ipad[64], opad[64];
    for (int i = 0; i < 64; ++i) { ipad[i] = k[i] ^ 0x36; opad[i] = k[i] ^ 0x5c; }
    sha256 inner; inner.update(ipad, 64); inner.update(msg.data(), msg.size());
    const auto ih = inner.finish();
    sha256 outer; outer.update(opad, 64); outer.update(ih.data(), ih.size());
    return outer.finish();
}
inline key32 hkdf32(std::span<const std::uint8_t> salt, std::span<const std::uint8_t> ikm, std::span<const std::uint8_t> info) {
    // Extract with the salt as the key (an empty salt is 32 zero bytes, as the RFC says), then one
    // round of Expand: T(1) = HMAC(PRK, info || 0x01), which is the 32 bytes wanted.
    std::uint8_t zero[32]{};
    const auto prk = hmac_sha256(salt.empty() ? std::span<const std::uint8_t>(zero, 32) : salt, ikm);
    bytes t1(info.begin(), info.end()); t1.push_back(1);
    return hmac_sha256(prk, t1);
}

// ---- ChaCha20-Poly1305 (RFC 8439) ----------------------------------------------------------------------------
namespace detail {
inline std::uint32_t load32(const std::uint8_t* p) { return std::uint32_t(p[0]) | (std::uint32_t(p[1]) << 8) | (std::uint32_t(p[2]) << 16) | (std::uint32_t(p[3]) << 24); }
inline void store32(std::uint8_t* p, std::uint32_t v) { p[0] = std::uint8_t(v); p[1] = std::uint8_t(v >> 8); p[2] = std::uint8_t(v >> 16); p[3] = std::uint8_t(v >> 24); }
inline std::uint32_t rotl(std::uint32_t x, int n) { return (x << n) | (x >> (32 - n)); }
inline void quarter(std::uint32_t& a, std::uint32_t& b, std::uint32_t& c, std::uint32_t& d) {
    a += b; d ^= a; d = rotl(d, 16);
    c += d; b ^= c; b = rotl(b, 12);
    a += b; d ^= a; d = rotl(d, 8);
    c += d; b ^= c; b = rotl(b, 7);
}
inline void chacha20_block(const std::uint8_t key[32], std::uint32_t counter, const std::uint8_t nonce[12], std::uint8_t out[64]) {
    std::uint32_t s[16] = {0x61707865, 0x3320646e, 0x79622d32, 0x6b206574};
    for (int i = 0; i < 8; ++i) s[4 + i] = load32(key + 4 * i);
    s[12] = counter;
    for (int i = 0; i < 3; ++i) s[13 + i] = load32(nonce + 4 * i);
    std::uint32_t x[16];
    std::memcpy(x, s, sizeof x);
    for (int i = 0; i < 10; ++i) {
        quarter(x[0], x[4], x[8], x[12]); quarter(x[1], x[5], x[9], x[13]); quarter(x[2], x[6], x[10], x[14]); quarter(x[3], x[7], x[11], x[15]);
        quarter(x[0], x[5], x[10], x[15]); quarter(x[1], x[6], x[11], x[12]); quarter(x[2], x[7], x[8], x[13]); quarter(x[3], x[4], x[9], x[14]);
    }
    for (int i = 0; i < 16; ++i) store32(out + 4 * i, x[i] + s[i]);
}
inline void chacha20_xor(const std::uint8_t key[32], const std::uint8_t nonce[12], std::uint32_t counter, const std::uint8_t* in, std::uint8_t* out, std::size_t n) {
    std::uint8_t ks[64];
    while (n) {
        chacha20_block(key, counter++, nonce, ks);
        const std::size_t take = std::min<std::size_t>(64, n);
        for (std::size_t i = 0; i < take; ++i) out[i] = in[i] ^ ks[i];
        in += take; out += take; n -= take;
    }
}
// Poly1305 with 26-bit limbs (the well known "donna" arrangement), one shot.
inline std::array<std::uint8_t, 16> poly1305(const std::uint8_t key[32], const std::uint8_t* m, std::size_t n) {
    std::uint32_t r0 = load32(key) & 0x3ffffff, r1 = (load32(key + 3) >> 2) & 0x3ffff03, r2 = (load32(key + 6) >> 4) & 0x3ffc0ff,
                  r3 = (load32(key + 9) >> 6) & 0x3f03fff, r4 = (load32(key + 12) >> 8) & 0x00fffff;
    const std::uint32_t s1 = r1 * 5, s2 = r2 * 5, s3 = r3 * 5, s4 = r4 * 5;
    std::uint32_t h0 = 0, h1 = 0, h2 = 0, h3 = 0, h4 = 0;
    std::uint8_t block[16];
    while (n) {
        std::uint32_t hibit = 1u << 24;
        std::size_t take = 16;
        if (n < 16) { std::memset(block, 0, 16); std::memcpy(block, m, n); block[n] = 1; hibit = 0; take = n; }
        const std::uint8_t* b = n < 16 ? block : m;
        h0 += load32(b) & 0x3ffffff; h1 += (load32(b + 3) >> 2) & 0x3ffffff; h2 += (load32(b + 6) >> 4) & 0x3ffffff;
        h3 += (load32(b + 9) >> 6) & 0x3ffffff; h4 += (load32(b + 12) >> 8) | hibit;
        std::uint64_t d0 = std::uint64_t(h0) * r0 + std::uint64_t(h1) * s4 + std::uint64_t(h2) * s3 + std::uint64_t(h3) * s2 + std::uint64_t(h4) * s1;
        std::uint64_t d1 = std::uint64_t(h0) * r1 + std::uint64_t(h1) * r0 + std::uint64_t(h2) * s4 + std::uint64_t(h3) * s3 + std::uint64_t(h4) * s2;
        std::uint64_t d2 = std::uint64_t(h0) * r2 + std::uint64_t(h1) * r1 + std::uint64_t(h2) * r0 + std::uint64_t(h3) * s4 + std::uint64_t(h4) * s3;
        std::uint64_t d3 = std::uint64_t(h0) * r3 + std::uint64_t(h1) * r2 + std::uint64_t(h2) * r1 + std::uint64_t(h3) * r0 + std::uint64_t(h4) * s4;
        std::uint64_t d4 = std::uint64_t(h0) * r4 + std::uint64_t(h1) * r3 + std::uint64_t(h2) * r2 + std::uint64_t(h3) * r1 + std::uint64_t(h4) * r0;
        std::uint32_t c = std::uint32_t(d0 >> 26); h0 = std::uint32_t(d0) & 0x3ffffff; d1 += c;
        c = std::uint32_t(d1 >> 26); h1 = std::uint32_t(d1) & 0x3ffffff; d2 += c;
        c = std::uint32_t(d2 >> 26); h2 = std::uint32_t(d2) & 0x3ffffff; d3 += c;
        c = std::uint32_t(d3 >> 26); h3 = std::uint32_t(d3) & 0x3ffffff; d4 += c;
        c = std::uint32_t(d4 >> 26); h4 = std::uint32_t(d4) & 0x3ffffff; h0 += c * 5;
        c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
        m += take; n -= take;
    }
    std::uint32_t c = h1 >> 26; h1 &= 0x3ffffff; h2 += c; c = h2 >> 26; h2 &= 0x3ffffff; h3 += c; c = h3 >> 26; h3 &= 0x3ffffff; h4 += c;
    c = h4 >> 26; h4 &= 0x3ffffff; h0 += c * 5; c = h0 >> 26; h0 &= 0x3ffffff; h1 += c;
    std::uint32_t g0 = h0 + 5; c = g0 >> 26; g0 &= 0x3ffffff; std::uint32_t g1 = h1 + c; c = g1 >> 26; g1 &= 0x3ffffff;
    std::uint32_t g2 = h2 + c; c = g2 >> 26; g2 &= 0x3ffffff; std::uint32_t g3 = h3 + c; c = g3 >> 26; g3 &= 0x3ffffff;
    std::uint32_t g4 = h4 + c - (1u << 26);
    std::uint32_t mask = (g4 >> 31) - 1;
    g0 &= mask; g1 &= mask; g2 &= mask; g3 &= mask; g4 &= mask; mask = ~mask;
    h0 = (h0 & mask) | g0; h1 = (h1 & mask) | g1; h2 = (h2 & mask) | g2; h3 = (h3 & mask) | g3; h4 = (h4 & mask) | g4;
    h0 = (h0 | (h1 << 26)) & 0xffffffff; h1 = ((h1 >> 6) | (h2 << 20)) & 0xffffffff; h2 = ((h2 >> 12) | (h3 << 14)) & 0xffffffff; h3 = ((h3 >> 18) | (h4 << 8)) & 0xffffffff;
    std::uint64_t f = std::uint64_t(h0) + load32(key + 16); h0 = std::uint32_t(f);
    f = std::uint64_t(h1) + load32(key + 20) + (f >> 32); h1 = std::uint32_t(f);
    f = std::uint64_t(h2) + load32(key + 24) + (f >> 32); h2 = std::uint32_t(f);
    f = std::uint64_t(h3) + load32(key + 28) + (f >> 32); h3 = std::uint32_t(f);
    std::array<std::uint8_t, 16> tag{};
    store32(tag.data(), h0); store32(tag.data() + 4, h1); store32(tag.data() + 8, h2); store32(tag.data() + 12, h3);
    return tag;
}
inline std::array<std::uint8_t, 16> aead_tag(const std::uint8_t key[32], const std::uint8_t nonce[12], std::span<const std::uint8_t> ad, std::span<const std::uint8_t> ct) {
    std::uint8_t otk[64];
    chacha20_block(key, 0, nonce, otk);
    bytes mac;
    mac.reserve(ad.size() + ct.size() + 32);
    mac.insert(mac.end(), ad.begin(), ad.end()); while (mac.size() % 16) mac.push_back(0);
    mac.insert(mac.end(), ct.begin(), ct.end()); while (mac.size() % 16) mac.push_back(0);
    for (int i = 0; i < 8; ++i) mac.push_back(std::uint8_t(std::uint64_t(ad.size()) >> (8 * i)));
    for (int i = 0; i < 8; ++i) mac.push_back(std::uint8_t(std::uint64_t(ct.size()) >> (8 * i)));
    return poly1305(otk, mac.data(), mac.size());
}
} // namespace detail

inline std::optional<bytes> aead_seal(const key32& key, const std::array<std::uint8_t, 12>& nonce, std::span<const std::uint8_t> plaintext, std::span<const std::uint8_t> ad) {
    bytes out(plaintext.size() + 16);
    detail::chacha20_xor(key.data(), nonce.data(), 1, plaintext.data(), out.data(), plaintext.size());
    const auto tag = detail::aead_tag(key.data(), nonce.data(), ad, std::span<const std::uint8_t>(out.data(), plaintext.size()));
    std::memcpy(out.data() + plaintext.size(), tag.data(), 16);
    return out;
}
inline std::optional<bytes> aead_open(const key32& key, const std::array<std::uint8_t, 12>& nonce, std::span<const std::uint8_t> sealed, std::span<const std::uint8_t> ad) {
    if (sealed.size() < 16) return std::nullopt;
    const std::size_t n = sealed.size() - 16;
    const auto tag = detail::aead_tag(key.data(), nonce.data(), ad, sealed.subspan(0, n));
    std::uint8_t diff = 0;
    for (int i = 0; i < 16; ++i) diff |= tag[static_cast<std::size_t>(i)] ^ sealed[n + static_cast<std::size_t>(i)];
    if (diff) return std::nullopt;
    bytes out(n);
    detail::chacha20_xor(key.data(), nonce.data(), 1, sealed.data(), out.data(), n);
    return out;
}

// ---- X25519 and Ed25519 (TweetNaCl) ---------------------------------------------------------------------------
struct x25519 {
    key32 priv{}, pub{};
    static std::optional<x25519> generate() {
        x25519 k; random_bytes(k.priv.data(), 32);
        crypto_scalarmult_curve25519_tweet_base(k.pub.data(), k.priv.data());
        return k;
    }
    static std::optional<x25519> from_private(const key32& priv) {
        x25519 k; k.priv = priv;
        crypto_scalarmult_curve25519_tweet_base(k.pub.data(), k.priv.data());
        return k;
    }
    std::optional<key32> shared(const key32& peer_pub) const {
        key32 out{};
        crypto_scalarmult_curve25519_tweet(out.data(), priv.data(), peer_pub.data());
        // An all-zero result means a low order point: refused, as OpenSSL refuses it.
        std::uint8_t any = 0; for (auto b : out) any |= b;
        if (!any) return std::nullopt;
        return out;
    }
};
inline std::optional<key32> ed25519_public(const key32& seed) {
    key32 out{};
    if (converge_ed25519_public_from_seed(out.data(), seed.data()) != 0) return std::nullopt;
    return out;
}
inline std::optional<sig64> ed25519_sign(const key32& seed, std::span<const std::uint8_t> message) {
    auto pk = ed25519_public(seed);
    if (!pk) return std::nullopt;
    std::uint8_t sk[64]; std::memcpy(sk, seed.data(), 32); std::memcpy(sk + 32, pk->data(), 32);
    bytes sm(message.size() + 64);
    unsigned long long smlen = 0;
    crypto_sign_ed25519_tweet(sm.data(), &smlen, message.data(), message.size(), sk);
    sig64 sig{}; std::memcpy(sig.data(), sm.data(), 64);
    return sig;
}
inline std::optional<sig64> ed25519_sign(const key32& seed, std::string_view message) {
    return ed25519_sign(seed, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()));
}
inline bool ed25519_verify(const key32& pub, std::span<const std::uint8_t> message, const sig64& sig) {
    bytes sm(64 + message.size()); std::memcpy(sm.data(), sig.data(), 64); std::memcpy(sm.data() + 64, message.data(), message.size());
    bytes m(sm.size());
    unsigned long long mlen = 0;
    return crypto_sign_ed25519_tweet_open(m.data(), &mlen, sm.data(), sm.size(), pub.data()) == 0;
}
inline bool ed25519_verify(const key32& pub, std::string_view message, const sig64& sig) {
    return ed25519_verify(pub, std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(message.data()), message.size()), sig);
}

} // namespace converge::link::portable
