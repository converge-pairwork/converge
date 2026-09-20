#include "crypto.hpp"

#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/rand.h>
#include <openssl/sha.h>

#include <algorithm>
#include <cstring>
#include <memory>
#include <stdexcept>

namespace converge::crypto {

namespace {
struct PkeyDel { void operator()(EVP_PKEY* p) const { EVP_PKEY_free(p); } };
struct PctxDel { void operator()(EVP_PKEY_CTX* p) const { EVP_PKEY_CTX_free(p); } };
struct CctxDel { void operator()(EVP_CIPHER_CTX* p) const { EVP_CIPHER_CTX_free(p); } };
using Pkey = std::unique_ptr<EVP_PKEY, PkeyDel>;
using Pctx = std::unique_ptr<EVP_PKEY_CTX, PctxDel>;
using Cctx = std::unique_ptr<EVP_CIPHER_CTX, CctxDel>;

constexpr char kB64[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
} // namespace

std::string b64_encode(const std::uint8_t* p, std::size_t n) {
    std::string out;
    out.reserve((n + 2) / 3 * 4);
    for (std::size_t i = 0; i < n; i += 3) {
        std::uint32_t v = p[i] << 16 | (i + 1 < n ? p[i + 1] << 8 : 0) | (i + 2 < n ? p[i + 2] : 0);
        out.push_back(kB64[v >> 18 & 63]);
        out.push_back(kB64[v >> 12 & 63]);
        out.push_back(i + 1 < n ? kB64[v >> 6 & 63] : '=');
        out.push_back(i + 2 < n ? kB64[v & 63] : '=');
    }
    return out;
}

std::optional<Bytes> b64_decode(std::string_view s) {
    Bytes out;
    std::uint32_t acc = 0; int bits = 0;
    for (char c : s) {
        if (c == '=') break;
        const char* q = std::strchr(kB64, c);
        if (!q || c == '\0') return std::nullopt;
        acc = acc << 6 | static_cast<std::uint32_t>(q - kB64);
        bits += 6;
        if (bits >= 8) { bits -= 8; out.push_back(static_cast<std::uint8_t>(acc >> bits & 0xff)); }
    }
    return out;
}

std::string hex(const std::uint8_t* p, std::size_t n) {
    static constexpr char d[] = "0123456789abcdef";
    std::string s; s.reserve(n * 2);
    for (std::size_t i = 0; i < n; ++i) { s.push_back(d[p[i] >> 4]); s.push_back(d[p[i] & 15]); }
    return s;
}

std::array<std::uint8_t, 32> sha256(std::string_view data) {
    std::array<std::uint8_t, 32> h{};
    SHA256(reinterpret_cast<const unsigned char*>(data.data()), data.size(), h.data());
    return h;
}

Identity::Identity() {
    Pkey k(EVP_PKEY_Q_keygen(nullptr, nullptr, "X25519"));
    if (!k) throw std::runtime_error("X25519 keygen failed");
    std::size_t n = 32;
    if (EVP_PKEY_get_raw_private_key(k.get(), priv_.data(), &n) != 1 || n != 32) throw std::runtime_error("raw priv");
    n = 32;
    if (EVP_PKEY_get_raw_public_key(k.get(), pub_.data(), &n) != 1 || n != 32) throw std::runtime_error("raw pub");
}

Key32 Identity::shared_secret(const Key32& peer_pub) const {
    Pkey me(EVP_PKEY_new_raw_private_key(EVP_PKEY_X25519, nullptr, priv_.data(), 32));
    Pkey peer(EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, peer_pub.data(), 32));
    if (!me || !peer) throw std::runtime_error("X25519 key import");
    Pctx ctx(EVP_PKEY_CTX_new(me.get(), nullptr));
    Key32 out{};
    std::size_t n = 32;
    if (EVP_PKEY_derive_init(ctx.get()) != 1 || EVP_PKEY_derive_set_peer(ctx.get(), peer.get()) != 1 ||
        EVP_PKEY_derive(ctx.get(), out.data(), &n) != 1 || n != 32)
        throw std::runtime_error("X25519 derive");
    if (std::all_of(out.begin(), out.end(), [](auto b) { return b == 0; })) throw std::runtime_error("low-order peer key");
    return out;
}

namespace {
// Deterministic ordering of the two peers, independent of who called whom.
bool i_am_first(const Key32& mine, const Key32& theirs) {
    return std::lexicographical_compare(mine.begin(), mine.end(), theirs.begin(), theirs.end());
}
} // namespace

SessionKeys derive_session(const Key32& shared, const Key32& my_pub, const Key32& peer_pub,
                           std::string_view call_id) {
    if (call_id.empty()) throw std::runtime_error("missing call key context");
    const bool first = i_am_first(my_pub, peer_pub);
    const Key32& lo = first ? my_pub : peer_pub;
    const Key32& hi = first ? peer_pub : my_pub;
    std::array<std::uint8_t, 64> info{};
    std::copy(lo.begin(), lo.end(), info.begin());
    std::copy(hi.begin(), hi.end(), info.begin() + 32);

    Pctx ctx(EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr));
    static constexpr char salt[] = "converge-v3";
    std::array<std::uint8_t, 64> okm{};
    std::size_t n = okm.size();
    if (EVP_PKEY_derive_init(ctx.get()) != 1 ||
        EVP_PKEY_CTX_set_hkdf_md(ctx.get(), EVP_sha256()) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_salt(ctx.get(), reinterpret_cast<const unsigned char*>(salt), sizeof(salt) - 1) != 1 ||
        EVP_PKEY_CTX_set1_hkdf_key(ctx.get(), shared.data(), 32) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), info.data(), static_cast<int>(info.size())) != 1 ||
        EVP_PKEY_CTX_add1_hkdf_info(ctx.get(), reinterpret_cast<const unsigned char*>(call_id.data()), static_cast<int>(call_id.size())) != 1 ||
        EVP_PKEY_derive(ctx.get(), okm.data(), &n) != 1 || n != 64)
        throw std::runtime_error("HKDF");
    Key32 klo{}, khi{};
    std::copy_n(okm.begin(), 32, klo.begin());
    std::copy_n(okm.begin() + 32, 32, khi.begin());
    // klo protects frames sent by the lower public key, khi those of the higher one.
    return first ? SessionKeys{klo, khi} : SessionKeys{khi, klo};
}

Sealer::Sealer(SessionKeys keys, const Key32& my_pub, const Key32& peer_pub)
    : k_(keys),
      aad_send_(hex(my_pub.data(), my_pub.size())), aad_recv_(hex(peer_pub.data(), peer_pub.size())),
      dir_send_(i_am_first(my_pub, peer_pub) ? 0 : 1),
      dir_recv_(i_am_first(my_pub, peer_pub) ? 1 : 0) {}

static void put_nonce(std::uint8_t* n, std::uint32_t dir, std::uint64_t ctr) {
    for (int i = 0; i < 4; ++i) n[i] = static_cast<std::uint8_t>(dir >> (24 - 8 * i));
    for (int i = 0; i < 8; ++i) n[4 + i] = static_cast<std::uint8_t>(ctr >> (56 - 8 * i));
}

Bytes Sealer::seal(std::string_view pt) {
    Bytes out(12 + pt.size() + 16);
    put_nonce(out.data(), dir_send_, ctr_send_++);
    Cctx c(EVP_CIPHER_CTX_new());
    int len = 0;
    if (EVP_EncryptInit_ex(c.get(), EVP_chacha20_poly1305(), nullptr, k_.send.data(), out.data()) != 1 ||
        EVP_EncryptUpdate(c.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(aad_send_.data()), static_cast<int>(aad_send_.size())) != 1 ||
        EVP_EncryptUpdate(c.get(), out.data() + 12, &len, reinterpret_cast<const unsigned char*>(pt.data()), static_cast<int>(pt.size())) != 1 ||
        EVP_EncryptFinal_ex(c.get(), out.data() + 12 + len, &len) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_AEAD_GET_TAG, 16, out.data() + 12 + pt.size()) != 1)
        throw std::runtime_error("seal");
    return out;
}

std::optional<std::string> Sealer::open(const std::uint8_t* f, std::size_t n) {
    if (n < 12 + 16) return std::nullopt;
    std::uint32_t dir = 0; std::uint64_t ctr = 0;
    for (int i = 0; i < 4; ++i) dir = dir << 8 | f[i];
    for (int i = 0; i < 8; ++i) ctr = ctr << 8 | f[4 + i];
    if (dir != dir_recv_ || ctr < ctr_recv_expected_) return std::nullopt;   // wrong direction or replay
    const std::size_t ct_len = n - 12 - 16;
    std::string pt(ct_len, '\0');
    Cctx c(EVP_CIPHER_CTX_new());
    int len = 0;
    std::uint8_t tag[16];
    std::memcpy(tag, f + 12 + ct_len, 16);
    if (EVP_DecryptInit_ex(c.get(), EVP_chacha20_poly1305(), nullptr, k_.recv.data(), f) != 1 ||
        EVP_DecryptUpdate(c.get(), nullptr, &len, reinterpret_cast<const unsigned char*>(aad_recv_.data()), static_cast<int>(aad_recv_.size())) != 1 ||
        EVP_DecryptUpdate(c.get(), reinterpret_cast<unsigned char*>(pt.data()), &len, f + 12, static_cast<int>(ct_len)) != 1 ||
        EVP_CIPHER_CTX_ctrl(c.get(), EVP_CTRL_AEAD_SET_TAG, 16, tag) != 1 ||
        EVP_DecryptFinal_ex(c.get(), reinterpret_cast<unsigned char*>(pt.data()) + len, &len) != 1)
        return std::nullopt;
    ctr_recv_expected_ = ctr + 1;
    return pt;
}

std::string sas(const Key32& a, const Key32& b) {
    const Key32& lo = std::lexicographical_compare(a.begin(), a.end(), b.begin(), b.end()) ? a : b;
    const Key32& hi = (&lo == &a) ? b : a;
    std::string m(reinterpret_cast<const char*>(lo.data()), 32);
    m.append(reinterpret_cast<const char*>(hi.data()), 32);
    auto h = sha256(m);
    std::uint32_t v = (h[0] << 16 | h[1] << 8 | h[2]) % 1'000'000;
    char buf[8];
    std::snprintf(buf, sizeof buf, "%06u", v);
    return buf;
}

} // namespace converge::crypto
