// The CONVERGE link, protocol v4: every message a bridge, the web application and the relay
// exchange, as QSF frames. One definition, taken by the relay and the web application from the
// client release, so that every end of the link speaks from the same file.
//
// The link is an encrypted, authenticated byte stream that does not care what carries it: a
// WebSocket (one frame per binary message), or a raw TCP socket (a 4 byte preamble, then each
// frame prefixed by its u32 little endian length). Its security does not depend on TLS.
//
//   1. client_hello   plaintext: the client's ephemeral X25519 key, a nonce, its features
//   2. relay_hello    the relay's ephemeral key in the clear, then relay_hello_body sealed under
//                     the ephemeral-ephemeral key (it carries the relay's static key), then a
//                     confirmation tag under the key that includes ephemeral-static, which only
//                     the holder of that static key can produce
//   3. client_auth    the first frame of the encrypted stream: who the client is (an Ed25519
//                     key, which is a Solana address), its signature over the transcript, its
//                     per process call key, and what it wants (be a member, redeem an invitation,
//                     wait to be paired, resume a session)
//   4. welcome        the relay's first frame, or link_error
//
// From frame 3 on, everything is sealed with ChaCha20-Poly1305 under per direction keys derived
// from the handshake, with counter nonces and the transcript hash as associated data
// (handshake.hpp). Payload frames between peers are sealed a second time, end to end, exactly as
// in v3 (call keys, HKDF salt converge-v3): the relay forwards ciphertext it cannot read.
//
// Conventions: an identity is 32 raw Ed25519 public key bytes on the wire and its base58 (a Solana
// address) in text; a handle is "cvh_" + the first 12 hex digits of SHA-256(identity); every token
// quantity is u64 CONVERGE base units. Fields are positional. A schema change appends fields and
// bumps that message's `version`.
#pragma once

#include "qsf.hpp"

#include <array>
#include <cstdint>
#include <string>
#include <vector>

namespace converge::link {

inline constexpr std::uint16_t protocol_version = 4;
inline constexpr char raw_preamble[4] = {'C', 'V', 'G', '4'};   // first bytes on a raw TCP carrier

using key32 = std::array<std::uint8_t, 32>;
using sig64 = std::array<std::uint8_t, 64>;

namespace limits {
inline constexpr std::size_t payload = 256 * 1024;              // one sealed peer payload
inline constexpr std::size_t frame = payload + 4096;            // one link frame, sealed, with headers
inline constexpr std::size_t text = 256, label = 64, handle = 32, code = 96, features = 16, feature = 32,
                             certificate_body = 512, certificates = 4, domain = 128, session = 64,
                             reason = 128, blob = 1024, identity_text = 44, sas = 8;
}

// Codes 1000 and up are the link's. The account messages of the web application (converge::wire,
// codes 1 to 44) travel inside the same stream unchanged: the relay dispatches on the code.
enum class code : std::uint32_t {
    // handshake
    client_hello = 1000, relay_hello = 1001, relay_hello_body = 1002, client_auth = 1003, welcome = 1004, link_error = 1005,
    ping = 1006, pong = 1007,
    // calls
    call = 1010, calling = 1011, incoming = 1012, accept = 1013, reject = 1014, hangup = 1015, connected = 1016, bye = 1017,
    peer_away = 1018, peer_back = 1019,
    // payload
    payload = 1020, ack = 1021, usage = 1022,
    // referee mode (the barrier of v3, exchange-v3 semantics, one frame per former JSON message)
    referee_propose = 1030, referee_answer = 1031, referee_offer = 1032, referee_pending = 1033, referee_mode = 1034,
    referee_declined = 1035, round_prepare = 1036, round_ready = 1037, commit = 1038, commit_held = 1039, commits = 1040,
    reveal_held = 1041, round_release = 1042, round_expired = 1043, release_held = 1044,
    // certificates and pairing
    certificate_submit = 1050, certificate_revoke = 1051, paired = 1052,
    // the relay's own key, for receipts
    relay_key = 1060,
};

enum class intent : std::uint8_t {
    member = 0,          // I am this key; admit me under the account my certificates (or my own key) give
    redeem_invite = 1,   // a host paid invitation: register me as a member of the host's account
    link_invite = 2,     // a split invitation: introduce my account and the host's
    pair = 3,            // wait, pending, until a wallet signs a certificate for this key (or admit me on my own key)
};
enum class scope : std::uint8_t { member = 0, manager = 1, account = 2 };
enum class role : std::uint8_t { caller = 0, callee = 1 };
enum class carrier : std::uint8_t { websocket = 0, raw = 1 };

#define CV_TRY(var, expr) auto var = (expr); if (!var) return std::unexpected(var.error())
#define CV_OPEN(T) CV_TRY(opened, qsf::reader::open(frame, static_cast<std::uint32_t>(T::k), T::version)); auto& r = *opened; T m
#define CV_DONE() if (auto d = r.done(); !d) return std::unexpected(d.error()); return m

namespace detail {
template <class E> qsf::result<E> get_enum(qsf::reader& r, std::uint8_t max) {
    auto v = r.get<std::uint8_t>();
    if (!v) return std::unexpected(v.error());
    if (*v > max) return std::unexpected(qsf::error::bad_value);
    return static_cast<E>(*v);
}
template <std::size_t N> qsf::result<std::array<std::uint8_t, N>> get_fixed(qsf::reader& r) {
    auto b = r.get_bytes(N);
    if (!b) return std::unexpected(b.error());
    if (b->size() != N) return std::unexpected(qsf::error::bad_value);
    std::array<std::uint8_t, N> out{};
    std::copy(b->begin(), b->end(), out.begin());
    return out;
}
// An optional fixed field: empty bytes means absent.
template <std::size_t N> qsf::result<std::array<std::uint8_t, N>> get_fixed_or_zero(qsf::reader& r, bool& present) {
    auto b = r.get_bytes(N);
    if (!b) return std::unexpected(b.error());
    std::array<std::uint8_t, N> out{};
    present = !b->empty();
    if (present && b->size() != N) return std::unexpected(qsf::error::bad_value);
    if (present) std::copy(b->begin(), b->end(), out.begin());
    return out;
}
inline qsf::result<std::vector<std::string>> get_strings(qsf::reader& r, std::size_t max_count, std::size_t max_len) {
    auto n = r.get<std::uint16_t>();
    if (!n) return std::unexpected(n.error());
    if (*n > max_count) return std::unexpected(qsf::error::too_long);
    std::vector<std::string> out;
    for (std::uint16_t i = 0; i < *n; ++i) { CV_TRY(s, r.get_string(max_len)); out.push_back(*s); }
    return out;
}
inline qsf::writer& put_strings(qsf::writer& w, const std::vector<std::string>& v) {
    w.put(static_cast<std::uint16_t>(v.size()));
    for (const auto& s : v) w.put_string(s);
    return w;
}
template <std::size_t N> qsf::writer& put_fixed(qsf::writer& w, const std::array<std::uint8_t, N>& a) { return w.put_bytes(a.data(), a.size()); }
template <std::size_t N> qsf::writer& put_fixed_if(qsf::writer& w, bool present, const std::array<std::uint8_t, N>& a) {
    return present ? w.put_bytes(a.data(), a.size()) : w.put_bytes(nullptr, 0);
}
} // namespace detail

// ---- a certificate: what a wallet (or a manager) signs to admit a key -------------------------------------
// `body` is the exact text signed, in the converge-member-v1 layout (README); the signer is the
// account's wallet, or a manager key whose own certificate is chained before it. The signature
// is over the body bytes as a wallet signs a message, or over Solana's off-chain message wrapper
// of them, as the CLI signs; a verifier accepts either.
struct certificate {
    std::string body;
    key32 signer{};
    sig64 signature{};
};
inline qsf::writer& put_certificates(qsf::writer& w, const std::vector<certificate>& cs) {
    w.put(static_cast<std::uint16_t>(cs.size()));
    for (const auto& c : cs) { w.put_string(c.body); detail::put_fixed(w, c.signer); detail::put_fixed(w, c.signature); }
    return w;
}
inline qsf::result<std::vector<certificate>> get_certificates(qsf::reader& r) {
    auto n = r.get<std::uint16_t>();
    if (!n) return std::unexpected(n.error());
    if (*n > limits::certificates) return std::unexpected(qsf::error::too_long);
    std::vector<certificate> out;
    for (std::uint16_t i = 0; i < *n; ++i) {
        certificate c;
        CV_TRY(b, r.get_string(limits::certificate_body)); c.body = *b;
        CV_TRY(s, detail::get_fixed<32>(r)); c.signer = *s;
        CV_TRY(g, detail::get_fixed<64>(r)); c.signature = *g;
        out.push_back(std::move(c));
    }
    return out;
}

// ---- handshake ------------------------------------------------------------------------------------------
struct client_hello {
    static constexpr code k = code::client_hello; static constexpr std::uint16_t version = 1;
    std::uint16_t protocol = protocol_version;
    key32 ephemeral{};
    std::array<std::uint8_t, 16> nonce{};
    std::vector<std::string> features;
    carrier via = carrier::websocket;
    qsf::blob encode() const {
        qsf::writer w(static_cast<std::uint32_t>(k), version);
        w.put(protocol); detail::put_fixed(w, ephemeral); detail::put_fixed(w, nonce);
        detail::put_strings(w, features); w.put(static_cast<std::uint8_t>(via));
        return w.finish();
    }
    static qsf::result<client_hello> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(client_hello);
        CV_TRY(p, r.get<std::uint16_t>()); m.protocol = *p;
        CV_TRY(e, detail::get_fixed<32>(r)); m.ephemeral = *e;
        CV_TRY(n, detail::get_fixed<16>(r)); m.nonce = *n;
        CV_TRY(f, detail::get_strings(r, limits::features, limits::feature)); m.features = *f;
        CV_TRY(c, detail::get_enum<carrier>(r, 1)); m.via = *c;
        CV_DONE();
    }
};

// Sealed inside relay_hello: only a party that completed the ephemeral exchange reads it.
struct relay_hello_body {
    static constexpr code k = code::relay_hello_body; static constexpr std::uint16_t version = 1;
    key32 static_key{};                  // the relay's long-lived X25519 key; the client checks it against what it expects
    std::array<std::uint8_t, 16> nonce{};
    std::uint16_t protocol = protocol_version;
    std::vector<std::string> features;
    std::string domain;                  // the relay's name, part of what identities sign
    qsf::blob encode() const {
        qsf::writer w(static_cast<std::uint32_t>(k), version);
        detail::put_fixed(w, static_key); detail::put_fixed(w, nonce); w.put(protocol);
        detail::put_strings(w, features); w.put_string(domain);
        return w.finish();
    }
    static qsf::result<relay_hello_body> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(relay_hello_body);
        CV_TRY(s, detail::get_fixed<32>(r)); m.static_key = *s;
        CV_TRY(n, detail::get_fixed<16>(r)); m.nonce = *n;
        CV_TRY(p, r.get<std::uint16_t>()); m.protocol = *p;
        CV_TRY(f, detail::get_strings(r, limits::features, limits::feature)); m.features = *f;
        CV_TRY(d, r.get_string(limits::domain)); m.domain = *d;
        CV_DONE();
    }
};

struct relay_hello {
    static constexpr code k = code::relay_hello; static constexpr std::uint16_t version = 1;
    key32 ephemeral{};
    qsf::blob sealed_body;               // relay_hello_body, sealed (handshake.hpp says how)
    std::array<std::uint8_t, 16> confirm{};   // a tag only the holder of the static key can produce
    qsf::blob encode() const {
        qsf::writer w(static_cast<std::uint32_t>(k), version);
        detail::put_fixed(w, ephemeral); w.put_bytes(sealed_body.data(), sealed_body.size()); detail::put_fixed(w, confirm);
        return w.finish();
    }
    static qsf::result<relay_hello> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(relay_hello);
        CV_TRY(e, detail::get_fixed<32>(r)); m.ephemeral = *e;
        CV_TRY(b, r.get_bytes(limits::blob)); m.sealed_body = *b;
        CV_TRY(c, detail::get_fixed<16>(r)); m.confirm = *c;
        CV_DONE();
    }
};

// The first sealed frame from the client. `signature` is over the auth text (handshake.hpp), which
// binds the identity to this handshake's transcript, the relay's domain and its static key.
struct client_auth {
    static constexpr code k = code::client_auth; static constexpr std::uint16_t version = 1;
    key32 identity{};                    // Ed25519 public key = the Solana address
    sig64 signature{};
    key32 call_key{};                    // per process X25519 key for peer payload sealing (as v3's `pub`)
    sig64 call_key_signature{};          // over the session binding text: this call key belongs to this identity
    std::vector<certificate> certificates;   // admission under someone else's account; empty = my own key is my account
    intent want = intent::member;
    std::string invite_code, alias;      // redeem_invite / link_invite; alias for the new member
    std::string resume_session;          // a session to resume (empty = none)
    key32 resume_key{};                  // its resume key, as welcome gave it
    std::uint64_t last_seq_seen = 0;     // resume: the last payload sequence this side read
    qsf::blob encode() const {
        qsf::writer w(static_cast<std::uint32_t>(k), version);
        detail::put_fixed(w, identity); detail::put_fixed(w, signature); detail::put_fixed(w, call_key); detail::put_fixed(w, call_key_signature);
        put_certificates(w, certificates); w.put(static_cast<std::uint8_t>(want)); w.put_string(invite_code).put_string(alias);
        w.put_string(resume_session); detail::put_fixed(w, resume_key); w.put(last_seq_seen);
        return w.finish();
    }
    static qsf::result<client_auth> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(client_auth);
        CV_TRY(i, detail::get_fixed<32>(r)); m.identity = *i;
        CV_TRY(s, detail::get_fixed<64>(r)); m.signature = *s;
        CV_TRY(c, detail::get_fixed<32>(r)); m.call_key = *c;
        CV_TRY(cs, detail::get_fixed<64>(r)); m.call_key_signature = *cs;
        CV_TRY(ce, get_certificates(r)); m.certificates = *ce;
        CV_TRY(wa, detail::get_enum<intent>(r, 3)); m.want = *wa;
        CV_TRY(ic, r.get_string(limits::code)); m.invite_code = *ic;
        CV_TRY(al, r.get_string(limits::label)); m.alias = *al;
        CV_TRY(rs, r.get_string(limits::session)); m.resume_session = *rs;
        CV_TRY(rk, detail::get_fixed<32>(r)); m.resume_key = *rk;
        CV_TRY(ls, r.get<std::uint64_t>()); m.last_seq_seen = *ls;
        CV_DONE();
    }
};

struct welcome {
    static constexpr code k = code::welcome; static constexpr std::uint16_t version = 1;
    std::string session;                 // this session's id; with resume_key it survives the socket
    key32 resume_key{};
    bool resumed = false;                // this welcome re-attached an existing session (and its call)
    std::uint64_t last_seq_seen = 0;     // resume: the last payload sequence the relay delivered to this side
    std::string handle, alias, account;
    scope granted = scope::member;
    std::uint64_t balance = 0, unfunded_message_count = 0;
    bool pending = false;                // intent pair: not admitted yet; `paired` follows when a certificate arrives
    std::vector<std::string> features;
    key32 receipt_key{};                 // the relay's Ed25519 key that signs round receipts
    std::int64_t server_time = 0;
    std::uint32_t member_limit = 0, call_limit = 0;
    qsf::blob encode() const {
        qsf::writer w(static_cast<std::uint32_t>(k), version);
        w.put_string(session); detail::put_fixed(w, resume_key); w.put_bool(resumed).put(last_seq_seen);
        w.put_string(handle).put_string(alias).put_string(account).put(static_cast<std::uint8_t>(granted));
        w.put(balance).put(unfunded_message_count).put_bool(pending);
        detail::put_strings(w, features); detail::put_fixed(w, receipt_key); w.put(server_time).put(member_limit).put(call_limit);
        return w.finish();
    }
    static qsf::result<welcome> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(welcome);
        CV_TRY(se, r.get_string(limits::session)); m.session = *se;
        CV_TRY(rk, detail::get_fixed<32>(r)); m.resume_key = *rk;
        CV_TRY(re, r.get_bool()); m.resumed = *re;
        CV_TRY(ls, r.get<std::uint64_t>()); m.last_seq_seen = *ls;
        CV_TRY(h, r.get_string(limits::handle)); m.handle = *h;
        CV_TRY(al, r.get_string(limits::label)); m.alias = *al;
        CV_TRY(ac, r.get_string(limits::text)); m.account = *ac;
        CV_TRY(sc, detail::get_enum<scope>(r, 2)); m.granted = *sc;
        CV_TRY(ba, r.get<std::uint64_t>()); m.balance = *ba;
        CV_TRY(uc, r.get<std::uint64_t>()); m.unfunded_message_count = *uc;
        CV_TRY(pe, r.get_bool()); m.pending = *pe;
        CV_TRY(f, detail::get_strings(r, limits::features, limits::feature)); m.features = *f;
        CV_TRY(rc, detail::get_fixed<32>(r)); m.receipt_key = *rc;
        CV_TRY(st, r.get<std::int64_t>()); m.server_time = *st;
        CV_TRY(ml, r.get<std::uint32_t>()); m.member_limit = *ml;
        CV_TRY(cl, r.get<std::uint32_t>()); m.call_limit = *cl;
        CV_DONE();
    }
};

// Any request may be answered with this; during the handshake it ends the connection.
struct link_error {
    static constexpr code k = code::link_error; static constexpr std::uint16_t version = 1;
    std::string code_name, message;      // code_name: the v3 error codes (bad_signature, unknown_peer, ...), plus the v4 ones
    std::string call_id;                 // when the error concerns a call
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(code_name).put_string(message).put_string(call_id).finish(); }
    static qsf::result<link_error> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(link_error);
        CV_TRY(c, r.get_string(limits::label)); m.code_name = *c;
        CV_TRY(t, r.get_string(limits::text)); m.message = *t;
        CV_TRY(i, r.get_string(limits::handle)); m.call_id = *i;
        CV_DONE();
    }
};

template <code C> struct time_message {
    static constexpr code k = C; static constexpr std::uint16_t version = 1;
    std::uint64_t t = 0;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put(t).finish(); }
    static qsf::result<time_message> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(time_message);
        CV_TRY(v, r.get<std::uint64_t>()); m.t = *v;
        CV_DONE();
    }
};
using ping = time_message<code::ping>;
using pong = time_message<code::pong>;

// ---- calls ----------------------------------------------------------------------------------------------
template <code C> struct call_id_message {
    static constexpr code k = C; static constexpr std::uint16_t version = 1;
    std::string call_id;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(call_id).finish(); }
    static qsf::result<call_id_message> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(call_id_message);
        CV_TRY(c, r.get_string(limits::handle)); m.call_id = *c;
        CV_DONE();
    }
};
using accept = call_id_message<code::accept>;
using reject = call_id_message<code::reject>;
using hangup = call_id_message<code::hangup>;        // empty call_id: the current call
using peer_away = call_id_message<code::peer_away>;
using peer_back = call_id_message<code::peer_back>;
using round_prepare = call_id_message<code::round_prepare>;

struct call {
    static constexpr code k = code::call; static constexpr std::uint16_t version = 1;
    std::string to;                      // a handle, or an alias within the caller's account
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(to).finish(); }
    static qsf::result<call> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(call);
        CV_TRY(t, r.get_string(limits::label)); m.to = *t;
        CV_DONE();
    }
};

struct calling {
    static constexpr code k = code::calling; static constexpr std::uint16_t version = 1;
    std::string call_id, to, alias;
    bool automatic = false;              // the callee accepts automatically
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(call_id).put_string(to).put_string(alias).put_bool(automatic).finish(); }
    static qsf::result<calling> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(calling);
        CV_TRY(c, r.get_string(limits::handle)); m.call_id = *c;
        CV_TRY(t, r.get_string(limits::handle)); m.to = *t;
        CV_TRY(a, r.get_string(limits::label)); m.alias = *a;
        CV_TRY(u, r.get_bool()); m.automatic = *u;
        CV_DONE();
    }
};

struct incoming {
    static constexpr code k = code::incoming; static constexpr std::uint16_t version = 1;
    std::string call_id, from, from_alias;
    bool same_account = false, automatic = false;
    qsf::blob encode() const {
        return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(call_id).put_string(from).put_string(from_alias)
            .put_bool(same_account).put_bool(automatic).finish();
    }
    static qsf::result<incoming> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(incoming);
        CV_TRY(c, r.get_string(limits::handle)); m.call_id = *c;
        CV_TRY(f, r.get_string(limits::handle)); m.from = *f;
        CV_TRY(a, r.get_string(limits::label)); m.from_alias = *a;
        CV_TRY(s, r.get_bool()); m.same_account = *s;
        CV_TRY(u, r.get_bool()); m.automatic = *u;
        CV_DONE();
    }
};

struct connected {
    static constexpr code k = code::connected; static constexpr std::uint16_t version = 1;
    std::string call_id;
    role mine = role::caller;
    std::string peer, peer_alias;
    key32 peer_call_key{}, peer_identity{};
    sig64 peer_call_key_signature{};
    std::uint16_t key_context_version = 3;   // the peer payload key schedule: v3's, unchanged
    // Which text the peer's call key signature is over: 4 = converge-session-v4 (identity base58,
    // call key base58); 1 = v3's converge-session-v1 (handle, call key base64), from a v3 peer.
    std::uint8_t binding_version = 4;
    qsf::blob encode() const {
        qsf::writer w(static_cast<std::uint32_t>(k), version);
        w.put_string(call_id).put(static_cast<std::uint8_t>(mine)).put_string(peer).put_string(peer_alias);
        detail::put_fixed(w, peer_call_key); detail::put_fixed(w, peer_identity); detail::put_fixed(w, peer_call_key_signature);
        return w.put(key_context_version).put(binding_version).finish();
    }
    static qsf::result<connected> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(connected);
        CV_TRY(c, r.get_string(limits::handle)); m.call_id = *c;
        CV_TRY(ro, detail::get_enum<role>(r, 1)); m.mine = *ro;
        CV_TRY(p, r.get_string(limits::handle)); m.peer = *p;
        CV_TRY(a, r.get_string(limits::label)); m.peer_alias = *a;
        CV_TRY(pk, detail::get_fixed<32>(r)); m.peer_call_key = *pk;
        CV_TRY(pi, detail::get_fixed<32>(r)); m.peer_identity = *pi;
        CV_TRY(ps, detail::get_fixed<64>(r)); m.peer_call_key_signature = *ps;
        CV_TRY(kv, r.get<std::uint16_t>()); m.key_context_version = *kv;
        CV_TRY(bv, r.get<std::uint8_t>()); m.binding_version = *bv;
        CV_DONE();
    }
};

struct bye {
    static constexpr code k = code::bye; static constexpr std::uint16_t version = 1;
    std::string call_id, reason;         // hangup, answered_elsewhere, peer_disconnected, peer_gone (grace elapsed)
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(call_id).put_string(reason).finish(); }
    static qsf::result<bye> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(bye);
        CV_TRY(c, r.get_string(limits::handle)); m.call_id = *c;
        CV_TRY(re, r.get_string(limits::reason)); m.reason = *re;
        CV_DONE();
    }
};

// ---- payload --------------------------------------------------------------------------------------------
// The sealed peer payload, numbered per direction of a call. The relay forwards `ciphertext`
// verbatim and answers the sender with `usage`; the receiver acknowledges by `ack` (or by the
// `last_seq_seen` of a resume), which is what lets a session survive its socket.
struct payload {
    static constexpr code k = code::payload; static constexpr std::uint16_t version = 1;
    std::uint64_t seq = 0;
    qsf::blob ciphertext;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put(seq).put_bytes(ciphertext.data(), ciphertext.size()).finish(); }
    static qsf::result<payload> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(payload);
        CV_TRY(s, r.get<std::uint64_t>()); m.seq = *s;
        CV_TRY(c, r.get_bytes(limits::payload)); m.ciphertext = *c;
        CV_DONE();
    }
};

struct ack {
    static constexpr code k = code::ack; static constexpr std::uint16_t version = 1;
    std::uint64_t seq = 0;               // every payload up to and including this one was read
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put(seq).finish(); }
    static qsf::result<ack> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(ack);
        CV_TRY(s, r.get<std::uint64_t>()); m.seq = *s;
        CV_DONE();
    }
};

// What the sender is told about one payload: charged or delayed, and the balance after it. It is
// for the sending user only and is never forwarded.
struct usage {
    static constexpr code k = code::usage; static constexpr std::uint16_t version = 1;
    std::uint64_t seq = 0, units = 0, balance = 0;
    bool delayed = false;
    std::uint32_t delay_ms = 0;
    std::uint64_t unfunded_message_count = 0;
    std::string notice;                  // the reminder line, when delayed
    qsf::blob encode() const {
        return qsf::writer(static_cast<std::uint32_t>(k), version).put(seq).put(units).put(balance).put_bool(delayed).put(delay_ms)
            .put(unfunded_message_count).put_string(notice).finish();
    }
    static qsf::result<usage> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(usage);
        CV_TRY(s, r.get<std::uint64_t>()); m.seq = *s;
        CV_TRY(u, r.get<std::uint64_t>()); m.units = *u;
        CV_TRY(b, r.get<std::uint64_t>()); m.balance = *b;
        CV_TRY(d, r.get_bool()); m.delayed = *d;
        CV_TRY(dm, r.get<std::uint32_t>()); m.delay_ms = *dm;
        CV_TRY(uc, r.get<std::uint64_t>()); m.unfunded_message_count = *uc;
        CV_TRY(n, r.get_string(limits::text)); m.notice = *n;
        CV_DONE();
    }
};

// ---- referee mode ---------------------------------------------------------------------------------------
struct referee_propose {
    static constexpr code k = code::referee_propose; static constexpr std::uint16_t version = 1;
    bool on = true;
    std::uint32_t timeout_sec = 120;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_bool(on).put(timeout_sec).finish(); }
    static qsf::result<referee_propose> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(referee_propose);
        CV_TRY(o, r.get_bool()); m.on = *o;
        CV_TRY(t, r.get<std::uint32_t>()); m.timeout_sec = *t;
        CV_DONE();
    }
};
struct referee_answer {                  // accept or decline the peer's proposal
    static constexpr code k = code::referee_answer; static constexpr std::uint16_t version = 1;
    bool accepted = true;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_bool(accepted).finish(); }
    static qsf::result<referee_answer> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(referee_answer);
        CV_TRY(a, r.get_bool()); m.accepted = *a;
        CV_DONE();
    }
};
struct referee_offer {                   // the peer proposes
    static constexpr code k = code::referee_offer; static constexpr std::uint16_t version = 1;
    bool on = true;
    std::uint32_t timeout_sec = 120;
    std::string from;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_bool(on).put(timeout_sec).put_string(from).finish(); }
    static qsf::result<referee_offer> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(referee_offer);
        CV_TRY(o, r.get_bool()); m.on = *o;
        CV_TRY(t, r.get<std::uint32_t>()); m.timeout_sec = *t;
        CV_TRY(f, r.get_string(limits::handle)); m.from = *f;
        CV_DONE();
    }
};
template <code C> struct referee_state {  // referee_pending, referee_mode, referee_declined
    static constexpr code k = C; static constexpr std::uint16_t version = 1;
    bool on = true;
    std::uint32_t timeout_sec = 120;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_bool(on).put(timeout_sec).finish(); }
    static qsf::result<referee_state> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(referee_state);
        CV_TRY(o, r.get_bool()); m.on = *o;
        CV_TRY(t, r.get<std::uint32_t>()); m.timeout_sec = *t;
        CV_DONE();
    }
};
using referee_pending = referee_state<code::referee_pending>;
using referee_mode = referee_state<code::referee_mode>;
using referee_declined = referee_state<code::referee_declined>;

struct round_ready {
    static constexpr code k = code::round_ready; static constexpr std::uint16_t version = 1;
    std::string exchange_id;
    std::uint64_t round = 0;
    std::int64_t deadline = 0;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(exchange_id).put(round).put(deadline).finish(); }
    static qsf::result<round_ready> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(round_ready);
        CV_TRY(e, r.get_string(limits::handle)); m.exchange_id = *e;
        CV_TRY(ro, r.get<std::uint64_t>()); m.round = *ro;
        CV_TRY(d, r.get<std::int64_t>()); m.deadline = *d;
        CV_DONE();
    }
};
struct commit {
    static constexpr code k = code::commit; static constexpr std::uint16_t version = 1;
    std::string exchange_id;
    std::uint64_t round = 0;
    std::string hash;                    // sha256 hex of the payload to come
    sig64 signature{};                   // over converge-commit-v1 text, by the identity key (all zero: none)
    qsf::blob encode() const {
        qsf::writer w(static_cast<std::uint32_t>(k), version);
        w.put_string(exchange_id).put(round).put_string(hash); detail::put_fixed(w, signature);
        return w.finish();
    }
    static qsf::result<commit> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(commit);
        CV_TRY(e, r.get_string(limits::handle)); m.exchange_id = *e;
        CV_TRY(ro, r.get<std::uint64_t>()); m.round = *ro;
        CV_TRY(h, r.get_string(limits::label + 16)); m.hash = *h;
        CV_TRY(s, detail::get_fixed<64>(r)); m.signature = *s;
        CV_DONE();
    }
};
// The barrier is holding this side's commitment or reveal until the peer's is in.
template <code C> struct held_message {
    static constexpr code k = C; static constexpr std::uint16_t version = 1;
    std::string exchange_id;
    std::uint64_t round = 0;
    std::int64_t deadline = 0;           // commit_held: when the round expires; reveal_held: 0
    std::uint32_t delay_ms = 0;          // release_held: the pair is released after this delay (delayed delivery)
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(exchange_id).put(round).put(deadline).put(delay_ms).finish(); }
    static qsf::result<held_message> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(held_message);
        CV_TRY(e, r.get_string(limits::handle)); m.exchange_id = *e;
        CV_TRY(ro, r.get<std::uint64_t>()); m.round = *ro;
        CV_TRY(d, r.get<std::int64_t>()); m.deadline = *d;
        CV_TRY(dm, r.get<std::uint32_t>()); m.delay_ms = *dm;
        CV_DONE();
    }
};
using commit_held = held_message<code::commit_held>;
using reveal_held = held_message<code::reveal_held>;
using release_held = held_message<code::release_held>;

// The relay's attestation of a round: the receipt text (README) and its Ed25519 signature.
struct receipt {
    std::string call_id, exchange_id, phase, commit_a, commit_b;
    std::uint64_t round = 0;
    std::int64_t ts = 0;
    sig64 signature{};
};
inline qsf::writer& put_receipt(qsf::writer& w, const receipt& x) {
    w.put_string(x.call_id).put_string(x.exchange_id).put_string(x.phase).put_string(x.commit_a).put_string(x.commit_b).put(x.round).put(x.ts);
    return detail::put_fixed(w, x.signature);
}
inline qsf::result<receipt> get_receipt(qsf::reader& r) {
    receipt x;
    CV_TRY(c, r.get_string(limits::handle)); x.call_id = *c;
    CV_TRY(e, r.get_string(limits::handle)); x.exchange_id = *e;
    CV_TRY(p, r.get_string(limits::label)); x.phase = *p;
    CV_TRY(a, r.get_string(limits::label + 16)); x.commit_a = *a;
    CV_TRY(b, r.get_string(limits::label + 16)); x.commit_b = *b;
    CV_TRY(ro, r.get<std::uint64_t>()); x.round = *ro;
    CV_TRY(t, r.get<std::int64_t>()); x.ts = *t;
    CV_TRY(s, detail::get_fixed<64>(r)); x.signature = *s;
    return x;
}

struct commits {                         // both commitments are in; the receipt attests them
    static constexpr code k = code::commits; static constexpr std::uint16_t version = 1;
    std::string mine, peer;
    sig64 peer_signature{};
    receipt attestation;
    qsf::blob encode() const {
        qsf::writer w(static_cast<std::uint32_t>(k), version);
        w.put_string(mine).put_string(peer); detail::put_fixed(w, peer_signature); put_receipt(w, attestation);
        return w.finish();
    }
    static qsf::result<commits> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(commits);
        CV_TRY(mi, r.get_string(limits::label + 16)); m.mine = *mi;
        CV_TRY(pe, r.get_string(limits::label + 16)); m.peer = *pe;
        CV_TRY(ps, detail::get_fixed<64>(r)); m.peer_signature = *ps;
        CV_TRY(re, get_receipt(r)); m.attestation = *re;
        CV_DONE();
    }
};
struct round_release {                   // both reveals are in; the peer's payload follows
    static constexpr code k = code::round_release; static constexpr std::uint16_t version = 1;
    receipt attestation;
    qsf::blob encode() const { qsf::writer w(static_cast<std::uint32_t>(k), version); put_receipt(w, attestation); return w.finish(); }
    static qsf::result<round_release> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(round_release);
        CV_TRY(re, get_receipt(r)); m.attestation = *re;
        CV_DONE();
    }
};
struct round_expired {
    static constexpr code k = code::round_expired; static constexpr std::uint16_t version = 1;
    std::uint64_t round = 0;
    std::string reason;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put(round).put_string(reason).finish(); }
    static qsf::result<round_expired> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(round_expired);
        CV_TRY(ro, r.get<std::uint64_t>()); m.round = *ro;
        CV_TRY(re, r.get_string(limits::reason)); m.reason = *re;
        CV_DONE();
    }
};

// ---- certificates and pairing ---------------------------------------------------------------------------
// From a wallet session (the web application) or a manager: admit, or revoke, a key. A pending
// bridge whose key the certificate names is admitted on the spot and told so with `paired`.
struct certificate_submit {
    static constexpr code k = code::certificate_submit; static constexpr std::uint16_t version = 1;
    certificate cert;
    qsf::blob encode() const { qsf::writer w(static_cast<std::uint32_t>(k), version); put_certificates(w, {cert}); return w.finish(); }
    static qsf::result<certificate_submit> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(certificate_submit);
        CV_TRY(cs, get_certificates(r));
        if (cs->size() != 1) return std::unexpected(qsf::error::bad_value);
        m.cert = (*cs)[0];
        CV_DONE();
    }
};
struct certificate_revoke {
    static constexpr code k = code::certificate_revoke; static constexpr std::uint16_t version = 1;
    certificate revocation;              // a converge-revoke-v1 text, signed by the same signer
    qsf::blob encode() const { qsf::writer w(static_cast<std::uint32_t>(k), version); put_certificates(w, {revocation}); return w.finish(); }
    static qsf::result<certificate_revoke> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(certificate_revoke);
        CV_TRY(cs, get_certificates(r));
        if (cs->size() != 1) return std::unexpected(qsf::error::bad_value);
        m.revocation = (*cs)[0];
        CV_DONE();
    }
};
struct paired {                          // to a pending bridge: you are a member now; a full welcome follows
    static constexpr code k = code::paired; static constexpr std::uint16_t version = 1;
    std::string account, alias;
    scope granted = scope::member;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(account).put_string(alias).put(static_cast<std::uint8_t>(granted)).finish(); }
    static qsf::result<paired> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(paired);
        CV_TRY(a, r.get_string(limits::text)); m.account = *a;
        CV_TRY(al, r.get_string(limits::label)); m.alias = *al;
        CV_TRY(sc, detail::get_enum<scope>(r, 2)); m.granted = *sc;
        CV_DONE();
    }
};

struct relay_key {                       // the relay's receipt signing key, for anyone
    static constexpr code k = code::relay_key; static constexpr std::uint16_t version = 1;
    key32 receipt_key{};
    qsf::blob encode() const { qsf::writer w(static_cast<std::uint32_t>(k), version); detail::put_fixed(w, receipt_key); return w.finish(); }
    static qsf::result<relay_key> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(relay_key);
        CV_TRY(rk, detail::get_fixed<32>(r)); m.receipt_key = *rk;
        CV_DONE();
    }
};

#undef CV_TRY
#undef CV_OPEN
#undef CV_DONE

} // namespace converge::link
