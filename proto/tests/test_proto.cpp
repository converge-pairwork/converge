// The link protocol, checked on its own: every message round trips strictly, a full handshake
// between an initiator and a responder yields two channels that talk, every way of tampering
// with it is refused, and certificates verify exactly as specified.
#include "certificate.hpp"
#include "handshake.hpp"
#include "link.hpp"

#include <cstdio>
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
    client_hello ch; ch.ephemeral.fill(1); ch.nonce.fill(2); ch.features = {"call-keys-v3", "exchange-v3"}; ch.via = carrier::raw;
    strict(ch);
    auto d = client_hello::decode(ch.encode());
    CHECK(d && d->protocol == 4 && d->features.size() == 2 && d->via == carrier::raw);
    relay_hello_body rb; rb.static_key.fill(3); rb.nonce.fill(4); rb.features = {"x"}; rb.domain = "converge.pairwork.net";
    strict(rb);
    relay_hello rh; rh.ephemeral.fill(5); rh.sealed_body = {1, 2, 3}; rh.confirm.fill(6);
    strict(rh);
    client_auth ca; ca.identity.fill(7); ca.signature.fill(8); ca.call_key.fill(9); ca.call_key_signature.fill(10);
    ca.certificates = {{"body", {}, {}}}; ca.want = intent::redeem_invite; ca.invite_code = "cvi_abc"; ca.alias = "laptop";
    ca.resume_session = "sess_1"; ca.resume_key.fill(11); ca.last_seq_seen = 42;
    strict(ca);
    auto cad = client_auth::decode(ca.encode());
    CHECK(cad && cad->certificates.size() == 1 && cad->want == intent::redeem_invite && cad->last_seq_seen == 42 && cad->resume_session == "sess_1");
    welcome w; w.session = "sess_2"; w.resume_key.fill(12); w.resumed = true; w.last_seq_seen = 7; w.handle = "cvh_0123456789ab"; w.alias = "a";
    w.account = "sol_x"; w.granted = scope::manager; w.balance = 5; w.unfunded_message_count = 3; w.pending = false; w.features = {"f"};
    w.receipt_key.fill(13); w.server_time = 1; w.member_limit = 2; w.call_limit = 1;
    strict(w);
    strict(link_error{"bad_signature", "no", "call_1"});
    strict(ping{5}); strict(pong{5});
    strict(call{"alice"}); strict(calling{"call_1", "cvh_a", "alice", true}); strict(incoming{"call_1", "cvh_b", "bob", true, false});
    strict(accept{"call_1"}); strict(hangup{""});
    connected c; c.call_id = "call_1"; c.mine = role::callee; c.peer = "cvh_b"; c.peer_call_key.fill(1); c.peer_identity.fill(2); c.peer_call_key_signature.fill(3);
    strict(c);
    strict(bye{"call_1", "peer_gone"}); strict(peer_away{"call_1"});
    payload p; p.seq = 9; p.ciphertext = bytes(1000, 0xab);
    strict(p);
    strict(ack{9}); strict(usage{9, 100, 5, true, 3000, 3, "notice"});
    strict(referee_propose{true, 120}); strict(referee_answer{false}); strict(referee_offer{true, 60, "cvh_a"});
    strict(referee_mode{true, 60}); strict(round_prepare{"call_1"}); strict(round_ready{"ex_1", 2, 1700000000});
    commit cm; cm.exchange_id = "ex_1"; cm.round = 2; cm.hash = std::string(64, 'a'); cm.signature.fill(4);
    strict(cm);
    commits cs; cs.mine = "h1"; cs.peer = "h2"; cs.attestation = {"call_1", "ex_1", "commit", "h1", "h2", 2, 1700000000, {}};
    strict(cs);
    strict(round_release{cs.attestation}); strict(round_expired{"ex_1", 2, "peer did not commit"});
    strict(commit_held{"ex_1", 2, 1700000000, 0}); strict(reveal_held{"ex_1", 2, 0, 0}); strict(release_held{"ex_1", 2, 0, 250});
    certificate_submit sub; sub.cert = {"converge-member-v1", {}, {}};
    strict(sub);
    strict(paired{"sol_x", "laptop", scope::member});
    relay_key rk; rk.receipt_key.fill(9);
    strict(rk);
    // A payload above the limit is refused before allocation.
    payload big; big.seq = 1; big.ciphertext = bytes(limits::payload + 1, 0);
    CHECK(payload::decode(big.encode()).error() == qsf::error::too_long || payload::decode(big.encode()).error() == qsf::error::bad_size);
    // A certificate list above the limit is refused.
    client_auth many; many.certificates = std::vector<certificate>(limits::certificates + 1);
    CHECK(client_auth::decode(many.encode()).error() == qsf::error::too_long);
}

static void test_handshake() {
    auto relay_static = crypto::X25519::generate();
    CHECK(relay_static.has_value());
    responder relay(*relay_static, "converge.pairwork.net", {"resume", "certificates"});
    initiator client(relay_static->pub);
    auto m1 = client.hello({"resume"});
    CHECK(m1.has_value());
    auto m2 = relay.on_client_hello(*m1);
    CHECK(m2.has_value());
    auto body = client.on_relay_hello(*m2);
    CHECK(body.has_value() && body->domain == "converge.pairwork.net" && body->static_key == relay_static->pub && body->features.size() == 2);
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

static void test_certificates() {
    const auto wallet_seed = crypto::random_array<32>(), member_seed = crypto::random_array<32>(), manager_seed = crypto::random_array<32>();
    const auto wallet = *crypto::ed25519_public(wallet_seed), member = *crypto::ed25519_public(member_seed), manager = *crypto::ed25519_public(manager_seed);
    member_certificate mc{wallet, member, "laptop", scope::member, 0};
    auto parsed = parse_member_certificate(mc.body());
    CHECK(parsed && parsed->account == wallet && parsed->member == member && parsed->alias == "laptop" && parsed->granted == scope::member && parsed->expires == 0);
    // Signed plainly (a wallet's signMessage) and through the off-chain wrapper (the CLI): both verify.
    certificate plain{mc.body(), wallet, *crypto::ed25519_sign(wallet_seed, mc.body())};
    const auto wrapped = offchain_wrapper(mc.body());
    certificate cli{mc.body(), wallet, *crypto::ed25519_sign(wallet_seed, std::span<const std::uint8_t>(wrapped))};
    CHECK(verify_certificate_signature(plain) && verify_certificate_signature(cli));
    certificate forged = plain; forged.signature[3] ^= 1;
    CHECK(!verify_certificate_signature(forged));
    certificate wrong_signer = plain; wrong_signer.signer = member;
    CHECK(!verify_certificate_signature(wrong_signer));
    // A chain: wallet admits a manager, the manager admits a member.
    member_certificate mgr{wallet, manager, "ops", scope::manager, 0};
    certificate c_mgr{mgr.body(), wallet, *crypto::ed25519_sign(wallet_seed, mgr.body())};
    member_certificate via{wallet, member, "teammate", scope::member, 0};
    certificate c_via{via.body(), manager, *crypto::ed25519_sign(manager_seed, via.body())};
    auto ok = verify_chain({c_mgr, c_via}, member, 1'700'000'000);
    CHECK(ok && ok->first == wallet && ok->second.alias == "teammate" && ok->second.granted == scope::member);
    CHECK(verify_chain({plain}, member, 1'700'000'000).has_value());
    CHECK(!verify_chain({plain}, manager, 1'700'000'000));                        // names another key
    CHECK(!verify_chain({c_via}, member, 1'700'000'000));                         // a manager's certificate without the wallet's before it
    certificate c_bad_mgr = c_via; c_bad_mgr.signer = wallet;                     // claims the wallet signed what the manager signed
    CHECK(!verify_chain({c_mgr, c_bad_mgr}, member, 1'700'000'000));
    member_certificate not_mgr{wallet, manager, "ops", scope::member, 0};         // admitted as member only: cannot admit others
    certificate c_not_mgr{not_mgr.body(), wallet, *crypto::ed25519_sign(wallet_seed, not_mgr.body())};
    CHECK(!verify_chain({c_not_mgr, c_via}, member, 1'700'000'000));
    member_certificate expired{wallet, member, "old", scope::member, 1'600'000'000};
    certificate c_exp{expired.body(), wallet, *crypto::ed25519_sign(wallet_seed, expired.body())};
    CHECK(!verify_chain({c_exp}, member, 1'700'000'000) && verify_chain({c_exp}, member, 1'500'000'000).has_value());
    // Malformed bodies.
    CHECK(!parse_member_certificate("converge-member-v1\naccount: x\n"));
    CHECK(!parse_member_certificate(mc.body() + "\nextra: 1"));
    CHECK(!parse_member_certificate("converge-member-v2\n" + mc.body().substr(19)));
    revocation rv{wallet, member, 1'700'000'000};
    auto pr = parse_revocation(rv.body());
    CHECK(pr && pr->member == member && pr->issued == 1'700'000'000);
    // Texts the identities sign are what they say.
    key32 t{}; t.fill(0xaa);
    CHECK(auth_text("d", wallet, t, wallet).starts_with("converge-v4-auth\nd\n" + identity_text(wallet) + "\n" + std::string(64, 'a')));
    CHECK(commit_text("ex", 3, "h") == "converge-commit-v1\nex\n3\nh");
    CHECK(receipt_text({"c", "e", "commit", "a", "b", 1, 2, {}}) == "converge-receipt-v1\nc\ne\ncommit\n1\na\nb\n2");
}

int main() {
    test_messages(); test_handshake(); test_handshake_refusals(); test_certificates();
    if (failures) { std::fprintf(stderr, "%d failure(s)\n", failures); return 1; }
    std::puts("proto: all checks passed");
    return 0;
}
