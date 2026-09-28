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
//                     per process call key, and what it wants (connect, join an invitation,
//                     resume a session)
//   4. welcome        the relay's first frame, or link_error
//
// From frame 3 on, everything is sealed with ChaCha20-Poly1305 under per direction keys derived
// from the handshake, with counter nonces and the transcript hash as associated data
// (handshake.hpp). Payload frames between peers are sealed a second time, end to end, exactly as
// in v3 (call keys, HKDF salt converge-v3): the relay forwards ciphertext it cannot read.
//
// Conventions: an identity is 32 raw Ed25519 public key bytes on the wire and its base58 (a Solana
// address) in text; a handle is "cvh_" + the first 12 hex digits of SHA-256(identity); every token
// quantity is u64 CONVERGE base units. Fields are positional. Every end is built from this one
// file, so a message has one layout: a change changes it everywhere, with no older layout kept.
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
                             domain = 128, session = 64,
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
    // adding a bridge to an account
    paired = 1050, bridge_confirm = 1051,
    // who pays for a call's traffic
    billing_set = 1070, billing_prefs = 1071, billing_offer = 1072, billing_request = 1073, billing_answer = 1074,
    terms = 1075, delivery = 1076,
};

enum class intent : std::uint8_t {
    member = 0,          // I am this key: its own account, or the wallet's account it was added to
    join_invite = 1,     // connect my key and the inviter's, and answer their calls without asking
    guest = 2,           // no account: the web application before a wallet signs in (public frames only)
};
enum class role : std::uint8_t { caller = 0, callee = 1 };

// Who pays for a call's traffic (agent/protocol.md, Who pays). A side's
// preference is an offer, per role: what it is willing to pay, never what the other side must.
enum class offer : std::uint8_t {
    none = 0,            // I pay nothing
    own = 1,             // I pay what I send
    all = 2,             // I pay both directions
};
// A stored preference: an offer, or nothing set at this level (the next one down decides).
// `keep` only in billing_set: leave this field as it is.
enum class pref : std::uint8_t { none = 0, own = 1, all = 2, inherit = 3, keep = 4 };
// Where an effective offer comes from; a more specific level wins a tie between two offers.
enum class pref_level : std::uint8_t { builtin = 0, account = 1, bridge = 2, connection = 3 };
// Who pays one direction of a call, as the side receiving the frame sees it.
enum class payer : std::uint8_t { nobody = 0, me = 1, peer = 2 };
// How one direction is delivered: paid (at once), unpaid (nobody pays: late), or payer_short
// (the payer's balance does not cover it: late).
enum class delivery_state : std::uint8_t { paid = 0, unpaid = 1, payer_short = 2 };
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

// What a bridge says about itself when it connects, for its account's list of bridges: the
// release it runs, the operating system, the machine's name, the operating system account it runs
// under, and when it was installed (unix seconds, 0 = unknown). Informational: nothing is
// decided on it, and a web application or a script connecting leaves it empty.
struct bridge_info {
    std::string version, os, machine, os_user;
    std::int64_t installed_at = 0;
    bool empty() const { return version.empty() && os.empty() && machine.empty() && os_user.empty() && installed_at == 0; }
};

// The first sealed frame from the client. `signature` is over the auth text (handshake.hpp), which
// binds the identity to this handshake's transcript, the relay's domain and its static key.
struct client_auth {
    static constexpr code k = code::client_auth; static constexpr std::uint16_t version = 1;
    key32 identity{};                    // Ed25519 public key = the Solana address
    sig64 signature{};
    key32 call_key{};                    // per process X25519 key for peer payload sealing (as v3's `pub`)
    sig64 call_key_signature{};          // over the session binding text: this call key belongs to this identity
    intent want = intent::member;
    std::string invite_code, alias;      // join_invite; alias for this key when it is a new account
    std::string resume_session;          // a session to resume (empty = none)
    key32 resume_key{};                  // its resume key, as welcome gave it
    std::uint64_t last_seq_seen = 0;     // resume: the last payload sequence this side read
    bridge_info info;
    bool rings = true;                   // calls may ring here; false for a connection that only does one thing and closes
    qsf::blob encode() const {
        qsf::writer w(static_cast<std::uint32_t>(k), version);
        detail::put_fixed(w, identity); detail::put_fixed(w, signature); detail::put_fixed(w, call_key); detail::put_fixed(w, call_key_signature);
        w.put(static_cast<std::uint8_t>(want)); w.put_string(invite_code).put_string(alias);
        w.put_string(resume_session); detail::put_fixed(w, resume_key); w.put(last_seq_seen);
        w.put_string(info.version).put_string(info.os).put_string(info.machine).put_string(info.os_user).put(info.installed_at);
        w.put_bool(rings);
        return w.finish();
    }
    static qsf::result<client_auth> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(client_auth);
        CV_TRY(i, detail::get_fixed<32>(r)); m.identity = *i;
        CV_TRY(s, detail::get_fixed<64>(r)); m.signature = *s;
        CV_TRY(c, detail::get_fixed<32>(r)); m.call_key = *c;
        CV_TRY(cs, detail::get_fixed<64>(r)); m.call_key_signature = *cs;
        CV_TRY(wa, detail::get_enum<intent>(r, 2)); m.want = *wa;
        CV_TRY(ic, r.get_string(limits::code)); m.invite_code = *ic;
        CV_TRY(al, r.get_string(limits::label)); m.alias = *al;
        CV_TRY(rs, r.get_string(limits::session)); m.resume_session = *rs;
        CV_TRY(rk, detail::get_fixed<32>(r)); m.resume_key = *rk;
        CV_TRY(ls, r.get<std::uint64_t>()); m.last_seq_seen = *ls;
        CV_TRY(iv, r.get_string(limits::label)); m.info.version = *iv;
        CV_TRY(io, r.get_string(limits::label)); m.info.os = *io;
        CV_TRY(im, r.get_string(limits::label)); m.info.machine = *im;
        CV_TRY(iu, r.get_string(limits::label)); m.info.os_user = *iu;
        CV_TRY(ia, r.get<std::int64_t>()); m.info.installed_at = *ia;
        CV_TRY(rg, r.get_bool()); m.rings = *rg;
        CV_DONE();
    }
};

struct welcome {
    static constexpr code k = code::welcome; static constexpr std::uint16_t version = 1;
    std::string session;                 // this session's id; with resume_key it survives the socket
    key32 resume_key{};
    bool resumed = false;                // this welcome re-attached an existing session (and its call)
    std::uint64_t last_seq_seen = 0;     // resume: the last payload sequence the relay delivered to this side
    std::string handle, alias;
    std::uint64_t balance = 0;           // the account's CONVERGE balance, whichever account it is
    bool guest = false;                  // intent guest: no account; a wallet sign-in on the stream (wallet_auth_req) gives one
    std::vector<std::string> features;
    std::int64_t server_time = 0;
    std::string peer_handle;             // intent join_invite: the inviter's handle, the peer this key is now connected to
    std::string pairing_link;            // a key on its own account: the link that adds it to a wallet's account ("" otherwise)
    std::string wallet;                  // the Solana address of the wallet whose account this bridge is on ("" = its own account)
    qsf::blob encode() const {
        qsf::writer w(static_cast<std::uint32_t>(k), version);
        w.put_string(session); detail::put_fixed(w, resume_key); w.put_bool(resumed).put(last_seq_seen);
        w.put_string(handle).put_string(alias);
        w.put(balance).put_bool(guest);
        detail::put_strings(w, features); w.put(server_time);
        w.put_string(peer_handle).put_string(pairing_link).put_string(wallet);
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
        CV_TRY(ba, r.get<std::uint64_t>()); m.balance = *ba;
        CV_TRY(gu, r.get_bool()); m.guest = *gu;
        CV_TRY(f, detail::get_strings(r, limits::features, limits::feature)); m.features = *f;
        CV_TRY(st, r.get<std::int64_t>()); m.server_time = *st;
        CV_TRY(hh, r.get_string(limits::handle)); m.peer_handle = *hh;
        CV_TRY(pl, r.get_string(limits::text)); m.pairing_link = *pl;
        CV_TRY(wa, r.get_string(limits::identity_text)); m.wallet = *wa;
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
    bool automatic = false;              // the call connects without this side accepting
    qsf::blob encode() const {
        return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(call_id).put_string(from).put_string(from_alias)
            .put_bool(automatic).finish();
    }
    static qsf::result<incoming> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(incoming);
        CV_TRY(c, r.get_string(limits::handle)); m.call_id = *c;
        CV_TRY(f, r.get_string(limits::handle)); m.from = *f;
        CV_TRY(a, r.get_string(limits::label)); m.from_alias = *a;
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
    sig64 peer_call_key_signature{};     // over call_key_binding_text(peer_identity, peer_call_key)
    qsf::blob encode() const {
        qsf::writer w(static_cast<std::uint32_t>(k), version);
        w.put_string(call_id).put(static_cast<std::uint8_t>(mine)).put_string(peer).put_string(peer_alias);
        detail::put_fixed(w, peer_call_key); detail::put_fixed(w, peer_identity); detail::put_fixed(w, peer_call_key_signature);
        return w.finish();
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

// What the sender is told about one payload: what its own account was charged for it (0 when the
// peer pays or nobody does), that account's balance after it, and whether it goes out late. It is
// for the sending user only and is never forwarded; `delivery` says why and what would fix it.
struct usage {
    static constexpr code k = code::usage; static constexpr std::uint16_t version = 1;
    std::uint64_t seq = 0, units = 0, balance = 0;
    bool delayed = false;
    std::uint32_t delay_ms = 0;
    qsf::blob encode() const {
        return qsf::writer(static_cast<std::uint32_t>(k), version).put(seq).put(units).put(balance).put_bool(delayed).put(delay_ms).finish();
    }
    static qsf::result<usage> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(usage);
        CV_TRY(s, r.get<std::uint64_t>()); m.seq = *s;
        CV_TRY(u, r.get<std::uint64_t>()); m.units = *u;
        CV_TRY(b, r.get<std::uint64_t>()); m.balance = *b;
        CV_TRY(d, r.get_bool()); m.delayed = *d;
        CV_TRY(dm, r.get<std::uint32_t>()); m.delay_ms = *dm;
        CV_DONE();
    }
};

// ---- who pays ------------------------------------------------------------------------------------------
// A bridge sets its own preference: for itself (level bridge) or for one peer (level connection;
// `peer` "" means the peer of the current call). Each field is an offer, `inherit` to clear it, or
// `keep`; keep and keep only reads. The relay answers `billing_prefs`, and when the bridge is in a
// call the new terms go to both sides.
struct billing_set {
    static constexpr code k = code::billing_set; static constexpr std::uint16_t version = 1;
    pref_level level = pref_level::connection;
    std::string peer;
    pref as_caller = pref::keep, as_callee = pref::keep;
    qsf::blob encode() const {
        return qsf::writer(static_cast<std::uint32_t>(k), version).put(static_cast<std::uint8_t>(level)).put_string(peer)
            .put(static_cast<std::uint8_t>(as_caller)).put(static_cast<std::uint8_t>(as_callee)).finish();
    }
    static qsf::result<billing_set> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(billing_set);
        CV_TRY(l, detail::get_enum<pref_level>(r, 3)); m.level = *l;
        if (m.level != pref_level::bridge && m.level != pref_level::connection) return std::unexpected(qsf::error::bad_value);
        CV_TRY(p, r.get_string(limits::handle)); m.peer = *p;
        CV_TRY(c, detail::get_enum<pref>(r, 4)); m.as_caller = *c;
        CV_TRY(e, detail::get_enum<pref>(r, 4)); m.as_callee = *e;
        CV_DONE();
    }
};

// A bridge's preferences as they stand, level by level (`inherit` where a level sets nothing), and
// what they come to: the offer in force for each role and the level it comes from. `peer` names
// the connection ("" when there is none).
struct billing_prefs {
    static constexpr code k = code::billing_prefs; static constexpr std::uint16_t version = 1;
    std::string peer;
    pref account_caller = pref::inherit, account_callee = pref::inherit;
    pref bridge_caller = pref::inherit, bridge_callee = pref::inherit;
    pref connection_caller = pref::inherit, connection_callee = pref::inherit;
    offer as_caller = offer::all, as_callee = offer::none;
    pref_level as_caller_level = pref_level::builtin, as_callee_level = pref_level::builtin;
    qsf::blob encode() const {
        qsf::writer w(static_cast<std::uint32_t>(k), version);
        w.put_string(peer);
        for (auto v : {account_caller, account_callee, bridge_caller, bridge_callee, connection_caller, connection_callee})
            w.put(static_cast<std::uint8_t>(v));
        w.put(static_cast<std::uint8_t>(as_caller)).put(static_cast<std::uint8_t>(as_callee))
         .put(static_cast<std::uint8_t>(as_caller_level)).put(static_cast<std::uint8_t>(as_callee_level));
        return w.finish();
    }
    static qsf::result<billing_prefs> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(billing_prefs);
        CV_TRY(p, r.get_string(limits::handle)); m.peer = *p;
        for (auto* v : {&m.account_caller, &m.account_callee, &m.bridge_caller, &m.bridge_callee, &m.connection_caller, &m.connection_callee}) {
            CV_TRY(x, detail::get_enum<pref>(r, 3)); *v = *x;
        }
        CV_TRY(oc, detail::get_enum<offer>(r, 2)); m.as_caller = *oc;
        CV_TRY(oe, detail::get_enum<offer>(r, 2)); m.as_callee = *oe;
        CV_TRY(lc, detail::get_enum<pref_level>(r, 3)); m.as_caller_level = *lc;
        CV_TRY(le, detail::get_enum<pref_level>(r, 3)); m.as_callee_level = *le;
        CV_DONE();
    }
};

// "You pay": in a call, a bridge proposes the offers both sides would make for this connection,
// `mine` for itself and `yours` for the peer. The relay hands it to the peer as `billing_request`
// (from the peer's side: `theirs` is the proposer's, `yours` its own); the peer answers with
// `billing_answer`, which the relay passes back to the proposer. Accepting sets both sides'
// connection preferences for their roles in this call. One proposal is open per call; a new one
// replaces it, and it lapses with the call.
struct billing_offer {
    static constexpr code k = code::billing_offer; static constexpr std::uint16_t version = 1;
    offer mine = offer::none, yours = offer::all;
    qsf::blob encode() const {
        return qsf::writer(static_cast<std::uint32_t>(k), version).put(static_cast<std::uint8_t>(mine)).put(static_cast<std::uint8_t>(yours)).finish();
    }
    static qsf::result<billing_offer> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(billing_offer);
        CV_TRY(a, detail::get_enum<offer>(r, 2)); m.mine = *a;
        CV_TRY(b, detail::get_enum<offer>(r, 2)); m.yours = *b;
        CV_DONE();
    }
};
struct billing_request {
    static constexpr code k = code::billing_request; static constexpr std::uint16_t version = 1;
    std::string call_id;
    offer theirs = offer::none, yours = offer::all;
    qsf::blob encode() const {
        return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(call_id)
            .put(static_cast<std::uint8_t>(theirs)).put(static_cast<std::uint8_t>(yours)).finish();
    }
    static qsf::result<billing_request> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(billing_request);
        CV_TRY(c, r.get_string(limits::handle)); m.call_id = *c;
        CV_TRY(a, detail::get_enum<offer>(r, 2)); m.theirs = *a;
        CV_TRY(b, detail::get_enum<offer>(r, 2)); m.yours = *b;
        CV_DONE();
    }
};
struct billing_answer {
    static constexpr code k = code::billing_answer; static constexpr std::uint16_t version = 1;
    bool accept = false;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_bool(accept).finish(); }
    static qsf::result<billing_answer> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(billing_answer);
        CV_TRY(a, r.get_bool()); m.accept = *a;
        CV_DONE();
    }
};

// The terms of the current call, as this side sees them: who pays what it sends (`out`) and what
// the peer sends (`in`), the offer this side makes and where it comes from, and a proposal still
// open (0 none, 1 this side's, 2 the peer's, with the offers it names for this side and the peer).
// Sent to both sides when the call connects and whenever the terms or the proposal change.
struct terms {
    static constexpr code k = code::terms; static constexpr std::uint16_t version = 1;
    std::string call_id;
    payer out = payer::me, in = payer::peer;
    offer mine = offer::all;
    pref_level mine_level = pref_level::builtin;
    std::uint8_t pending = 0;
    offer pending_mine = offer::none, pending_peer = offer::none;
    qsf::blob encode() const {
        return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(call_id)
            .put(static_cast<std::uint8_t>(out)).put(static_cast<std::uint8_t>(in))
            .put(static_cast<std::uint8_t>(mine)).put(static_cast<std::uint8_t>(mine_level)).put(pending)
            .put(static_cast<std::uint8_t>(pending_mine)).put(static_cast<std::uint8_t>(pending_peer)).finish();
    }
    static qsf::result<terms> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(terms);
        CV_TRY(c, r.get_string(limits::handle)); m.call_id = *c;
        CV_TRY(o, detail::get_enum<payer>(r, 2)); m.out = *o;
        CV_TRY(i, detail::get_enum<payer>(r, 2)); m.in = *i;
        CV_TRY(mi, detail::get_enum<offer>(r, 2)); m.mine = *mi;
        CV_TRY(ml, detail::get_enum<pref_level>(r, 3)); m.mine_level = *ml;
        CV_TRY(pe, r.get<std::uint8_t>()); if (*pe > 2) return std::unexpected(qsf::error::bad_value); m.pending = *pe;
        CV_TRY(pm, detail::get_enum<offer>(r, 2)); m.pending_mine = *pm;
        CV_TRY(pp, detail::get_enum<offer>(r, 2)); m.pending_peer = *pp;
        CV_DONE();
    }
};

// How the call's two directions are delivered, sent to both sides when the call connects and
// whenever a direction's state changes, with this side's own account: the wallet it belongs to
// ("" when the bridge is its own account) and its CONVERGE balance. Never the peer's. From this a
// bridge tells its user what would lift a delay: an account, a balance, saying "I pay", or waiting.
struct delivery {
    static constexpr code k = code::delivery; static constexpr std::uint16_t version = 1;
    std::string call_id;
    delivery_state out = delivery_state::paid, in = delivery_state::paid;
    std::uint32_t out_delay_ms = 0, in_delay_ms = 0;   // what the next message in that direction waits
    std::string wallet;
    std::uint64_t balance = 0;
    qsf::blob encode() const {
        return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(call_id)
            .put(static_cast<std::uint8_t>(out)).put(static_cast<std::uint8_t>(in)).put(out_delay_ms).put(in_delay_ms)
            .put_string(wallet).put(balance).finish();
    }
    static qsf::result<delivery> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(delivery);
        CV_TRY(c, r.get_string(limits::handle)); m.call_id = *c;
        CV_TRY(o, detail::get_enum<delivery_state>(r, 2)); m.out = *o;
        CV_TRY(i, detail::get_enum<delivery_state>(r, 2)); m.in = *i;
        CV_TRY(od, r.get<std::uint32_t>()); m.out_delay_ms = *od;
        CV_TRY(id, r.get<std::uint32_t>()); m.in_delay_ms = *id;
        CV_TRY(w, r.get_string(limits::identity_text)); m.wallet = *w;
        CV_TRY(b, r.get<std::uint64_t>()); m.balance = *b;
        CV_DONE();
    }
};

// ---- adding a bridge to an account ---------------------------------------------------------------------
// To a bridge that confirmed: its name on the account it is on now, that account's wallet and its
// CONVERGE balance, as a welcome would say them.
struct paired {
    static constexpr code k = code::paired; static constexpr std::uint16_t version = 1;
    std::string alias, wallet;
    std::uint64_t balance = 0;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(alias).put_string(wallet).put(balance).finish(); }
    static qsf::result<paired> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(paired);
        CV_TRY(al, r.get_string(limits::label)); m.alias = *al;
        CV_TRY(wa, r.get_string(limits::identity_text)); m.wallet = *wa;
        CV_TRY(ba, r.get<std::uint64_t>()); m.balance = *ba;
        CV_DONE();
    }
};

// From a bridge on its own connection: the confirmation code a wallet's account showed when it
// asked to add this bridge by its address. The connection already proves the key, so the code is
// all it carries. The relay answers `paired` (the account the bridge is on now) or link_error.
struct bridge_confirm {
    static constexpr code k = code::bridge_confirm; static constexpr std::uint16_t version = 1;
    std::string confirm_code;
    qsf::blob encode() const { return qsf::writer(static_cast<std::uint32_t>(k), version).put_string(confirm_code).finish(); }
    static qsf::result<bridge_confirm> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(bridge_confirm);
        CV_TRY(c, r.get_string(limits::code)); m.confirm_code = *c;
        CV_DONE();
    }
};

// ---- invitations --------------------------------------------------------------------------------------
// The same codes and layouts as the web application's converge::wire (16, 31, 32): one message,
// whichever end sends it. A bridge asks for an invitation to itself; the relay answers with the
// code and the line to send. An invitation connects two keys and carries nothing about what it
// is for.
struct ok_reply {
    static constexpr std::uint32_t k = 16; static constexpr std::uint16_t version = 1;
    qsf::blob encode() const { return qsf::writer(k, version).finish(); }
    static qsf::result<ok_reply> decode(std::span<const std::uint8_t> frame) { CV_OPEN(ok_reply); CV_DONE(); }
};
struct invite_create_req {
    static constexpr std::uint32_t k = 31; static constexpr std::uint16_t version = 1;
    std::string handle;                      // the bridge the invitation connects to ("" = the sender)
    std::uint32_t ttl_sec = 7 * 86400, max_uses = 1;
    qsf::blob encode() const { return qsf::writer(k, version).put_string(handle).put(ttl_sec).put(max_uses).finish(); }
    static qsf::result<invite_create_req> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(invite_create_req);
        CV_TRY(h, r.get_string(limits::handle)); m.handle = *h;
        CV_TRY(tt, r.get<std::uint32_t>()); m.ttl_sec = *tt;
        CV_TRY(mu, r.get<std::uint32_t>()); m.max_uses = *mu;
        CV_DONE();
    }
};
struct invite_create_reply {
    static constexpr std::uint32_t k = 32; static constexpr std::uint16_t version = 1;
    std::string invite_code, handle, share;   // handle: the bridge the invitation connects to
    std::int64_t expires = 0;
    std::uint32_t max_uses = 1;
    qsf::blob encode() const {
        return qsf::writer(k, version).put_string(invite_code).put_string(handle).put_string(share).put(expires).put(max_uses).finish();
    }
    static qsf::result<invite_create_reply> decode(std::span<const std::uint8_t> frame) {
        CV_OPEN(invite_create_reply);
        CV_TRY(c, r.get_string(limits::code)); m.invite_code = *c;
        CV_TRY(h, r.get_string(limits::handle)); m.handle = *h;
        CV_TRY(s, r.get_string(limits::text)); m.share = *s;
        CV_TRY(ex, r.get<std::int64_t>()); m.expires = *ex;
        CV_TRY(mu, r.get<std::uint32_t>()); m.max_uses = *mu;
        CV_DONE();
    }
};


#undef CV_TRY
#undef CV_OPEN
#undef CV_DONE

} // namespace converge::link
