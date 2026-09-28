// The link protocol, checked on its own: every message round trips strictly, a full handshake
// between an initiator and a responder yields two channels that talk, every way of tampering
// with it is refused.
#include "handshake.hpp"
#include "link.hpp"

#include <cstdio>
#include <exception>
#include <stdexcept>
#include <cstring>

using namespace converge;
using namespace converge::link;

static int failures = 0;
#define CHECK(x) do { if (!(x)) { std::fprintf(stderr, "FAIL %s:%d: %s\n", __FILE__, __LINE__, #x); ++failures; } } while (0)

template <class T> static void strict(const T& message) {
    const auto frame = message.encode();
    CHECK(T::decode(frame).has_value());
    auto trailing = frame; trailing.push_back(0);
    CHECK(!T::decode(trailing));                                   // size lie
    const std::uint64_t body = trailing.size() - qsf::header_size;
    std::memcpy(trailing.data() + 8, &body, 8);
    CHECK(T::decode(trailing).error() == qsf::error::trailing_bytes);
    if (frame.size() > qsf::header_size) {
        auto cut = frame; cut.pop_back();
        const std::uint64_t less = cut.size() - qsf::header_size;
        std::memcpy(cut.data() + 8, &less, 8);
        CHECK(!T::decode(cut));
    }
    auto newer = frame; newer[2] = static_cast<std::uint8_t>(T::version + 1);
    CHECK(T::decode(newer).error() == qsf::error::bad_version);
    CHECK(!link_error::decode(frame) || T::k == code::link_error);   // never taken for another message
}

static void test_messages() {
    client_hello ch; ch.ephemeral.fill(1); ch.nonce.fill(2); ch.features = {"call-keys-v3"}; ch.via = carrier::raw;
    strict(ch);
    auto d = client_hello::decode(ch.encode());
    CHECK(d && d->protocol == 4 && d->features.size() == 1 && d->via == carrier::raw);
    relay_hello_body rb; rb.static_key.fill(3); rb.nonce.fill(4); rb.features = {"x"}; rb.domain = "converge.pairwork.net";
    strict(rb);
    relay_hello rh; rh.ephemeral.fill(5); rh.sealed_body = {1, 2, 3}; rh.confirm.fill(6);
    strict(rh);
    client_auth ca; ca.identity.fill(7); ca.signature.fill(8); ca.call_key.fill(9); ca.call_key_signature.fill(10);
    ca.want = intent::join_invite; ca.invite_code = "cvi_abc"; ca.alias = "laptop";
    ca.resume_session = "sess_1"; ca.resume_key.fill(11); ca.last_seq_seen = 42;
    strict(ca);
    auto cad = client_auth::decode(ca.encode());
    CHECK(cad && cad->want == intent::join_invite && cad->last_seq_seen == 42 && cad->resume_session == "sess_1");
    ca.info = {"0.2.4", "Linux", "laptop", "alice", 1790000000};
    strict(ca);
    cad = client_auth::decode(ca.encode());
    CHECK(cad && cad->info.machine == "laptop" && cad->info.os_user == "alice" && cad->info.installed_at == 1790000000);
    welcome w; w.session = "sess_2"; w.resume_key.fill(12); w.resumed = true; w.last_seq_seen = 7; w.handle = "cvh_0123456789ab"; w.alias = "a";
    w.balance = 5; w.features = {"f"};
    w.server_time = 1;
    strict(w);
    w.pairing_link = "https://converge.pairwork.net/#link/addr/code"; w.wallet = "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU";
    strict(w);
    CHECK(welcome::decode(w.encode())->pairing_link == w.pairing_link && welcome::decode(w.encode())->wallet == w.wallet);
    strict(bridge_confirm{"cvc_123"});
    strict(link_error{"bad_signature", "no", "call_1"});
    strict(ping{5}); strict(pong{5});
    strict(call{"alice"}); strict(calling{"call_1", "cvh_a", "alice", true}); strict(incoming{"call_1", "cvh_b", "bob", true});
    strict(accept{"call_1"}); strict(hangup{""});
    connected c; c.call_id = "call_1"; c.mine = role::callee; c.peer = "cvh_b"; c.peer_call_key.fill(1); c.peer_identity.fill(2); c.peer_call_key_signature.fill(3);
    strict(c);
    strict(bye{"call_1", "peer_gone"}); strict(peer_away{"call_1"});
    payload p; p.seq = 9; p.ciphertext = bytes(1000, 0xab);
    strict(p);
    strict(ack{9}); strict(usage{9, 100, 5, true, 3000});
    strict(billing_set{pref_level::connection, "cvh_b", pref::all, pref::inherit});
    strict(billing_set{pref_level::bridge, "", pref::keep, pref::own});
    {
        billing_prefs bp; bp.peer = "cvh_b"; bp.account_caller = pref::own; bp.connection_callee = pref::all;
        bp.as_caller = offer::own; bp.as_callee = offer::all; bp.as_caller_level = pref_level::account; bp.as_callee_level = pref_level::connection;
        strict(bp);
    }
    strict(billing_offer{offer::none, offer::all}); strict(billing_request{"call_1", offer::own, offer::own});
    strict(billing_answer{true});
    strict(terms{"call_1", payer::peer, payer::nobody, offer::none, pref_level::connection, 2, offer::all, offer::none});
    strict(delivery{"call_1", delivery_state::unpaid, delivery_state::payer_short, 3000, 5000, "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", 42});
    // billing_set names only the levels a bridge may set: not the account's, not the built-in.
    {
        auto f = billing_set{pref_level::bridge, "", pref::all, pref::all}.encode();
        f[qsf::header_size] = static_cast<std::uint8_t>(pref_level::account);
        CHECK(billing_set::decode(f).error() == qsf::error::bad_value);
    }
    strict(paired{"laptop", "7xKXtg2CW87d97TXJSDpbD5jBkheTqA83TZRuJosgAsU", 42});
    // A payload above the limit is refused before allocation.
    payload big; big.seq = 1; big.ciphertext = bytes(limits::payload + 1, 0);
    CHECK(payload::decode(big.encode()).error() == qsf::error::too_long || payload::decode(big.encode()).error() == qsf::error::bad_size);
    // An intent past the last one is refused.
    {
        auto f = client_auth{}.encode();
        f[qsf::header_size + (8 + 32) + (8 + 64) + (8 + 32) + (8 + 64)] = 3;   // each fixed field has its u64 length first
        CHECK(client_auth::decode(f).error() == qsf::error::bad_value);
    }
}

static void test_handshake() {
    auto relay_static = crypto::X25519::generate();
    CHECK(relay_static.has_value());
    responder relay(*relay_static, "converge.pairwork.net", {"resume"});
    initiator client(relay_static->pub);
    auto m1 = client.hello({"resume"});
    CHECK(m1.has_value());
    auto m2 = relay.on_client_hello(*m1);
    CHECK(m2.has_value());
    auto body = client.on_relay_hello(*m2);
    CHECK(body.has_value() && body->domain == "converge.pairwork.net" && body->static_key == relay_static->pub && body->features.size() == 1);
    CHECK(client.transcript() == relay.transcript());
    CHECK(relay.client().features == std::vector<std::string>{"resume"});

    // The stream: the first client frame is client_auth, signed by an identity that is a Solana address.
    const auto seed = crypto::random_array<32>();
    const auto identity = crypto::ed25519_public(seed);
    CHECK(identity.has_value());
    auto call_key = crypto::X25519::generate();
    client_auth a; a.identity = *identity; a.call_key = call_key->pub;
    a.signature = *crypto::ed25519_sign(seed, auth_text("converge.pairwork.net", *identity, client.transcript(), relay.static_public()));
    a.call_key_signature = *crypto::ed25519_sign(seed, call_key_binding_text(*identity, call_key->pub));
    auto sealed = client.stream().seal(a.encode());
    CHECK(sealed.has_value());
    auto opened = relay.stream().open(*sealed);
    CHECK(opened.has_value());
    auto got = client_auth::decode(*opened);
    CHECK(got && got->identity == *identity);
    CHECK(verify_client_auth(*got, "converge.pairwork.net", relay.transcript(), relay.static_public()));
    CHECK(!verify_client_auth(*got, "other.example", relay.transcript(), relay.static_public()));   // bound to the relay's name
    CHECK(handle_of(*identity).starts_with("cvh_") && handle_of(*identity).size() == 16);
    CHECK(identity_from_text(identity_text(*identity)) == *identity);

    // Both directions, many frames, counters in step.
    for (int i = 0; i < 50; ++i) {
        welcome w; w.session = "s" + std::to_string(i);
        auto s = relay.stream().seal(w.encode());
        auto o = client.stream().open(*s);
        CHECK(o && welcome::decode(*o)->session == w.session);
        auto s2 = client.stream().seal(ping{static_cast<std::uint64_t>(i)}.encode());
        auto o2 = relay.stream().open(*s2);
        CHECK(o2 && ping::decode(*o2)->t == static_cast<std::uint64_t>(i));
    }
    // A replayed frame, a reordered frame and a flipped bit are all refused.
    auto s = relay.stream().seal(pong{1}.encode());
    CHECK(client.stream().open(*s).has_value());
    CHECK(client.stream().open(*s).error() == hs_error::sealed);                 // replay
    auto s1 = relay.stream().seal(pong{2}.encode()), s2 = relay.stream().seal(pong{3}.encode());
    CHECK(client.stream().open(*s2).error() == hs_error::sealed);               // out of order
    (*s1)[5] ^= 1;
    CHECK(client.stream().open(*s1).error() == hs_error::sealed);               // tampered
}

static void test_handshake_refusals() {
    auto relay_static = crypto::X25519::generate();
    auto other_static = crypto::X25519::generate();
    // The client expects a different static key: the body opens but the key is wrong.
    {
        responder relay(*relay_static, "d", {});
        initiator client(other_static->pub);
        auto m2 = relay.on_client_hello(*client.hello({}));
        CHECK(client.on_relay_hello(*m2).error() == hs_error::static_key);
    }
    // An impostor that knows the real static public key but not its private half cannot confirm.
    {
        responder impostor(*other_static, "d", {});
        initiator client(relay_static->pub);
        auto m2 = impostor.on_client_hello(*client.hello({}));
        // Rewrite the sealed body to claim the real key: impossible without ck1, so simulate the
        // only thing an impostor can do, which is present its own key; refused as static_key.
        CHECK(client.on_relay_hello(*m2).error() == hs_error::static_key);
        // Trust on first use with a tampered confirm tag: refused as confirm.
        initiator tofu;
        responder relay(*relay_static, "d", {});
        auto m2b = relay.on_client_hello(*tofu.hello({}));
        auto rh = relay_hello::decode(*m2b);
        rh->confirm[0] ^= 1;
        CHECK(tofu.on_relay_hello(rh->encode()).error() == hs_error::confirm);
    }
    // A tampered client hello leaves the two sides with different transcripts.
    {
        responder relay(*relay_static, "d", {});
        initiator client(relay_static->pub);
        auto m1 = client.hello({});
        auto forged = *m1; forged[forged.size() - 1] ^= 1;
        auto m2 = relay.on_client_hello(forged);
        CHECK(m2.has_value());
        auto r = client.on_relay_hello(*m2);
        CHECK(!r.has_value());                                                   // ee differs: the body does not open
    }
    // Wrong protocol version.
    {
        responder relay(*relay_static, "d", {});
        client_hello ch; ch.protocol = 3;
        CHECK(relay.on_client_hello(ch.encode()).error() == hs_error::version);
    }
    // Steps out of order.
    {
        initiator client;
        CHECK(client.on_relay_hello(relay_hello{}.encode()).error() == hs_error::order);
        responder relay(*relay_static, "d", {});
        initiator first, second;
        CHECK(relay.on_client_hello(*first.hello({})).has_value());
        CHECK(relay.on_client_hello(*second.hello({})).error() == hs_error::order);
        // An all-zero ephemeral key (a low-order point) is refused by the primitive, never accepted.
        CHECK(responder(*relay_static, "d", {}).on_client_hello(client_hello{}.encode()).error() == hs_error::crypto);
    }
}

static void test_texts() {
    // Texts the identities sign are what they say.
    const auto wallet = *crypto::ed25519_public(crypto::random_array<32>());
    key32 t{}; t.fill(0xaa);
    CHECK(auth_text("d", wallet, t, wallet).starts_with("converge-v4-auth\nd\n" + identity_text(wallet) + "\n" + std::string(64, 'a')));
}

// The portable primitives against OpenSSL, on the published vectors and on random inputs: what
// the relay, the bridge and the web application all run must agree with what everyone else does.
#include <openssl/evp.h>
#include <openssl/kdf.h>
#include <openssl/sha.h>
static void test_portable_against_openssl() {
    using namespace converge::link::portable;
    // SHA-256: FIPS 180-4 "abc", then random lengths against OpenSSL.
    CHECK(crypto::hex(sha256::of("abc").data(), 32) == "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad");
    for (std::size_t n : {0u, 1u, 55u, 56u, 63u, 64u, 65u, 1000u, 70000u}) {
        bytes m(n); random_bytes(m.data(), n);
        key32 ref{}; SHA256(m.data(), n, ref.data());
        CHECK(sha256::of(m.data(), n) == ref);
    }
    // HKDF-SHA256 against OpenSSL.
    for (int i = 0; i < 20; ++i) {
        bytes salt(i % 3 == 0 ? 0 : 16), ikm(32), info(i % 5); random_bytes(salt.data(), salt.size()); random_bytes(ikm.data(), 32); random_bytes(info.data(), info.size());
        auto mine = hkdf32(salt, ikm, info);
        EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_HKDF, nullptr);
        key32 ref{}; std::size_t n = 32;
        // (an empty salt is the RFC's zero salt; OpenSSL takes that as "no salt given", not as an empty one)
        CHECK(EVP_PKEY_derive_init(ctx) == 1 && EVP_PKEY_CTX_set_hkdf_md(ctx, EVP_sha256()) == 1 &&
              (salt.empty() || EVP_PKEY_CTX_set1_hkdf_salt(ctx, salt.data(), static_cast<int>(salt.size())) == 1) &&
              EVP_PKEY_CTX_set1_hkdf_key(ctx, ikm.data(), 32) == 1 && EVP_PKEY_CTX_add1_hkdf_info(ctx, info.data(), static_cast<int>(info.size())) == 1 &&
              EVP_PKEY_derive(ctx, ref.data(), &n) == 1);
        EVP_PKEY_CTX_free(ctx);
        CHECK(mine == ref);
    }
    // ChaCha20-Poly1305: seal here, open with OpenSSL, and the other way; a flipped bit fails both.
    for (std::size_t n : {0u, 1u, 15u, 16u, 17u, 64u, 100u, 4096u}) {
        key32 key{}; random_bytes(key.data(), 32);
        std::array<std::uint8_t, 12> nonce{}; random_bytes(nonce.data(), 12);
        bytes pt(n), ad(7); random_bytes(pt.data(), n); random_bytes(ad.data(), 7);
        auto sealed = aead_seal(key, nonce, pt, ad);
        CHECK(sealed && sealed->size() == n + 16);
        EVP_CIPHER_CTX* c = EVP_CIPHER_CTX_new();
        bytes out(n); int len = 0;
        CHECK(EVP_DecryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) == 1);
        CHECK(EVP_DecryptUpdate(c, nullptr, &len, ad.data(), 7) == 1);
        if (n) CHECK(EVP_DecryptUpdate(c, out.data(), &len, sealed->data(), static_cast<int>(n)) == 1);
        CHECK(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_SET_TAG, 16, sealed->data() + n) == 1);
        CHECK(EVP_DecryptFinal_ex(c, out.data() + len, &len) == 1 && out == pt);
        EVP_CIPHER_CTX_free(c);
        // OpenSSL seals, we open.
        bytes ct(n + 16);
        c = EVP_CIPHER_CTX_new();
        CHECK(EVP_EncryptInit_ex(c, EVP_chacha20_poly1305(), nullptr, key.data(), nonce.data()) == 1);
        CHECK(EVP_EncryptUpdate(c, nullptr, &len, ad.data(), 7) == 1);
        if (n) CHECK(EVP_EncryptUpdate(c, ct.data(), &len, pt.data(), static_cast<int>(n)) == 1);
        CHECK(EVP_EncryptFinal_ex(c, ct.data() + n, &len) == 1);
        CHECK(EVP_CIPHER_CTX_ctrl(c, EVP_CTRL_AEAD_GET_TAG, 16, ct.data() + n) == 1);
        EVP_CIPHER_CTX_free(c);
        CHECK(ct == *sealed);
        CHECK(aead_open(key, nonce, ct, ad) == pt);
        auto bad = ct; bad[n / 2] ^= 1;
        CHECK(!aead_open(key, nonce, bad, ad));
    }
    // X25519 against OpenSSL: our secret with their public and the reverse agree.
    for (int i = 0; i < 10; ++i) {
        auto mine = x25519::generate();
        EVP_PKEY_CTX* kc = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, nullptr); EVP_PKEY* theirs = nullptr;
        CHECK(EVP_PKEY_keygen_init(kc) == 1 && EVP_PKEY_keygen(kc, &theirs) == 1);
        EVP_PKEY_CTX_free(kc);
        key32 their_pub{}; std::size_t n = 32; EVP_PKEY_get_raw_public_key(theirs, their_pub.data(), &n);
        auto ours = mine->shared(their_pub);
        EVP_PKEY* my_pub = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, nullptr, mine->pub.data(), 32);
        EVP_PKEY_CTX* dc = EVP_PKEY_CTX_new(theirs, nullptr);
        key32 ref{}; n = 32;
        CHECK(EVP_PKEY_derive_init(dc) == 1 && EVP_PKEY_derive_set_peer(dc, my_pub) == 1 && EVP_PKEY_derive(dc, ref.data(), &n) == 1);
        EVP_PKEY_CTX_free(dc); EVP_PKEY_free(my_pub); EVP_PKEY_free(theirs);
        CHECK(ours && *ours == ref);
    }
    // Ed25519 against OpenSSL: the same public key from a seed, signatures verify both ways.
    for (int i = 0; i < 10; ++i) {
        key32 seed{}; random_bytes(seed.data(), 32);
        auto pub = ed25519_public(seed);
        EVP_PKEY* k = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, seed.data(), 32);
        key32 ref{}; std::size_t n = 32; EVP_PKEY_get_raw_public_key(k, ref.data(), &n);
        CHECK(pub && *pub == ref);
        bytes msg(1 + static_cast<std::size_t>(i) * 37); random_bytes(msg.data(), msg.size());
        auto sig = ed25519_sign(seed, msg);
        EVP_MD_CTX* md = EVP_MD_CTX_new();
        CHECK(sig && EVP_DigestVerifyInit(md, nullptr, nullptr, nullptr, k) == 1 && EVP_DigestVerify(md, sig->data(), 64, msg.data(), msg.size()) == 1);
        EVP_MD_CTX_free(md);
        sig64 theirs{}; n = 64; md = EVP_MD_CTX_new();
        CHECK(EVP_DigestSignInit(md, nullptr, nullptr, nullptr, k) == 1 && EVP_DigestSign(md, theirs.data(), &n, msg.data(), msg.size()) == 1);
        EVP_MD_CTX_free(md); EVP_PKEY_free(k);
        CHECK(ed25519_verify(*pub, msg, theirs) && theirs == *sig);   // Ed25519 is deterministic: the same bytes
        auto bad = theirs; bad[10] ^= 1;
        CHECK(!ed25519_verify(*pub, msg, bad));
    }
}

int main() {
    // Unbuffered, and each suite named before it runs: a crash then says where, on a platform
    // where nothing buffered would otherwise reach the log.
    std::setvbuf(stdout, nullptr, _IONBF, 0);
    std::setvbuf(stderr, nullptr, _IONBF, 0);
    std::set_terminate([] { std::fputs("proto: terminate (an uncaught exception or a failed precondition)\n", stderr); std::abort(); });
    try {
        struct { const char* name; void (*run)(); } suites[] = {
            {"portable_against_openssl", test_portable_against_openssl}, {"messages", test_messages}, {"handshake", test_handshake},
            {"handshake_refusals", test_handshake_refusals}, {"texts", test_texts}};
        for (const auto& s : suites) { std::printf("  %s\n", s.name); s.run(); }
    } catch (const std::exception& e) {
        std::fprintf(stderr, "proto: exception: %s\n", e.what());
        return 1;
    }
    if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
    std::puts("proto: all checks passed");
    return 0;
}
