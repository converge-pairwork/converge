#include "relay_client.hpp"

#include "crypto.hpp"
#include "identity.hpp"
#include "handshake.hpp"
#include "link.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/json.hpp>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdio>

namespace converge {

namespace asio = boost::asio;
namespace beast = boost::beast;
namespace websocket = beast::websocket;
namespace ssl = asio::ssl;
namespace json = boost::json;
using asio::awaitable;
using asio::use_awaitable;
using tcp = asio::ip::tcp;

struct RelayClient::Impl {
    std::string url;
    Credentials creds;
    std::string pub;
    Url parsed{};
    asio::io_context io{1};
    ssl::context tls{ssl::context::tls_client};
    std::thread thread;
    std::atomic<bool> running{false}, is_connected{false};

    std::mutex mu;
    std::condition_variable cv;
    std::deque<RelayEvent> events;

    // outbound queue, drained by the io thread
    struct Out { std::vector<std::uint8_t> bytes; bool binary; };
    std::deque<Out> outq;
    std::function<void()> kick;     // set while connected: wakes the writer

    // v4: the relay key store, the handshake of the current connection, and the payload counter.
    std::function<std::optional<RelayClient::RelayKey>()> get_relay_key;
    std::function<void(const RelayClient::RelayKey&)> put_relay_key;
    std::optional<link::initiator> init;
    std::uint64_t out_seq = 0;          // per session: continues across a resume, so the relay can drop what it already relayed
    std::uint64_t last_in_seq = 0;      // the last payload sequence read, told to the relay on resume
    std::string session_id;             // from welcome; a reconnect within the grace period resumes it
    link::key32 resume_key{};
    bool v4() const { return creds.key.empty(); }

    void push(RelayEvent e) {
        { std::lock_guard lk(mu); events.push_back(std::move(e)); }
        cv.notify_all();
    }

    template <class Ws> awaitable<void> writer(Ws& ws, asio::steady_timer& wake, std::shared_ptr<bool> alive) {
        try {
            for (;;) {
                std::optional<Out> o;
                { std::lock_guard lk(mu); if (!outq.empty()) { o = std::move(outq.front()); outq.pop_front(); } }
                if (!o) {
                    wake.expires_at(asio::steady_timer::time_point::max());
                    boost::system::error_code ec;
                    co_await wake.async_wait(asio::redirect_error(use_awaitable, ec));
                    if (!running || !*alive) co_return;
                    continue;
                }
                if (v4()) {
                    auto plain = o->binary ? encode_payload(o->bytes) : encode_control(std::string(o->bytes.begin(), o->bytes.end()));
                    // The payload sequence is assigned when the frame is written, so a frame queued
                    // across a reconnect is numbered after the resume, not before it.
                    if (!plain) continue;
                    auto sealed = init->stream().seal(*plain);
                    if (!sealed) co_return;
                    ws.binary(true);
                    co_await ws.async_write(asio::buffer(*sealed), use_awaitable);
                    continue;
                }
                ws.binary(o->binary);
                co_await ws.async_write(asio::buffer(o->bytes), use_awaitable);
            }
        } catch (...) {}
    }

    // ---- v4: what the bridge says, from the JSON the MCP layer speaks, to link frames ----
    std::optional<qsf::blob> encode_payload(const std::vector<std::uint8_t>& sealed_peer_payload) {
        link::payload p; p.seq = ++out_seq; p.ciphertext = sealed_peer_payload;
        return p.encode();
    }
    std::optional<qsf::blob> encode_control(const std::string& text) {
        if (text == "ack") return link::ack{last_in_seq}.encode();
        json::object o;
        try { o = json::parse(text).as_object(); } catch (...) { return std::nullopt; }
        auto str = [&](const char* k, std::string d = "") { auto* v = o.if_contains(k); return v && v->is_string() ? std::string(v->get_string()) : d; };
        auto num = [&](const char* k, std::uint64_t d) { auto* v = o.if_contains(k); return v && v->is_number() ? v->to_number<std::uint64_t>() : d; };
        auto flag = [&](const char* k, bool d) { auto* v = o.if_contains(k); return v && v->is_bool() ? v->get_bool() : d; };
        const auto t = str("t");
        if (t == "ping") return link::ping{0}.encode();
        if (t == "call") return link::call{str("to")}.encode();
        if (t == "accept") return link::accept{str("call_id")}.encode();
        if (t == "reject") return link::reject{str("call_id")}.encode();
        if (t == "hangup") return link::hangup{str("call_id")}.encode();
        if (t == "invite_create")
            return link::invite_create_req{"", str("label"), static_cast<std::uint32_t>(num("ttl_sec", 7 * 86400)), static_cast<std::uint32_t>(num("max_uses", 1)),
                                           str("billing", "host") == "split" ? link::invite_billing::split : link::invite_billing::host}.encode();
        if (t == "referee_propose") return link::referee_propose{flag("on", true), static_cast<std::uint32_t>(num("timeout_sec", 120))}.encode();
        if (t == "referee_accept") return link::referee_answer{true}.encode();
        if (t == "referee_decline") return link::referee_answer{false}.encode();
        if (t == "round_prepare") return link::round_prepare{""}.encode();
        if (t == "commit") {
            link::commit c; c.exchange_id = str("exchange_id"); c.round = num("round", 0); c.hash = str("hash");
            if (auto sig = crypto::b64_decode(str("sig")); sig && sig->size() == 64) std::copy(sig->begin(), sig->end(), c.signature.begin());
            return c.encode();
        }
        return std::nullopt;
    }

    // ---- v4: what the relay says, as the JSON the MCP layer expects (v3's names and fields) ----
    static std::string b64(const std::uint8_t* p, std::size_t n) { return crypto::b64_encode(p, n); }
    template <std::size_t N> static bool nonzero(const std::array<std::uint8_t, N>& a) { return std::any_of(a.begin(), a.end(), [](auto b) { return b != 0; }); }
    static json::object receipt_json(const link::receipt& r) {
        json::object o{{"call_id", r.call_id}, {"exchange_id", r.exchange_id}, {"phase", r.phase}, {"round", r.round},
                       {"commit_a", r.commit_a}, {"commit_b", r.commit_b}, {"ts", r.ts}};
        if (nonzero(r.signature)) o["sig"] = b64(r.signature.data(), r.signature.size());
        return o;
    }
    void translate(const qsf::blob& f) {
        using namespace link;
        auto info = qsf::peek(f);
        if (!info) return;
        auto emit = [&](json::object o) { const auto t = std::string(o.at("t").as_string()); push({RelayEvent::Kind::text, t, json::serialize(o), {}}); };
        switch (static_cast<code>(info->code)) {
        case code::welcome: if (auto m = welcome::decode(f)) {
            if (!m->pending) { session_id = m->session; resume_key = m->resume_key; }
            if (!m->resumed) { out_seq = 0; last_in_seq = 0; }
            json::object o{{"t", "welcome"}, {"handle", m->handle}, {"alias", m->alias}, {"account", m->account}, {"balance", m->balance},
                           {"auth", "identity"}, {"pending", m->pending}, {"session", m->session}, {"resumed", m->resumed},
                           {"scope", m->granted == scope::account ? "account" : m->granted == scope::manager ? "manager" : "member"},
                           {"unfunded_message_count", m->unfunded_message_count}, {"host_handle", m->host_handle},
                           {"plan", json::object{{"members", m->member_limit}, {"concurrent_calls", m->call_limit}}}};
            json::array feats; for (const auto& x : m->features) feats.push_back(json::value(x));
            o["features"] = std::move(feats);
            emit(std::move(o));
        } return;
        case code::paired: if (auto m = paired::decode(f)) emit({{"t", "paired"}, {"account", m->account}, {"alias", m->alias}}); return;
        case code::link_error: if (auto m = link_error::decode(f)) emit({{"t", "error"}, {"code", m->code_name}, {"msg", m->message}, {"call_id", m->call_id}}); return;
        case code::pong: emit({{"t", "pong"}}); return;
        case code::calling: if (auto m = calling::decode(f)) emit({{"t", "calling"}, {"call_id", m->call_id}, {"to", m->to}, {"alias", m->alias}, {"auto", m->automatic}}); return;
        case code::incoming: if (auto m = incoming::decode(f))
            emit({{"t", "incoming"}, {"call_id", m->call_id}, {"from", m->from}, {"from_alias", m->from_alias}, {"same_account", m->same_account}, {"auto", m->automatic}});
            return;
        case code::connected: if (auto m = connected::decode(f)) {
            json::object o{{"t", "connected"}, {"call_id", m->call_id}, {"role", m->mine == role::caller ? "caller" : "callee"},
                           {"key_context_version", m->key_context_version}, {"peer", m->peer}, {"peer_alias", m->peer_alias},
                           {"peer_pub", b64(m->peer_call_key.data(), 32)}, {"binding_version", m->binding_version},
                           {"peer_identity", nonzero(m->peer_identity) ? ssh_line_from_raw(m->peer_identity, "") : std::string{}},
                           {"peer_pub_sig", nonzero(m->peer_call_key_signature) ? b64(m->peer_call_key_signature.data(), 64) : std::string{}}};
            emit(std::move(o));
        } return;
        case code::bye: if (auto m = bye::decode(f)) emit({{"t", "bye"}, {"call_id", m->call_id}, {"reason", m->reason}}); return;
        case code::peer_away: if (auto m = peer_away::decode(f)) emit({{"t", "peer_away"}, {"call_id", m->call_id}}); return;
        case code::peer_back: if (auto m = peer_back::decode(f)) emit({{"t", "peer_back"}, {"call_id", m->call_id}}); return;
        case code::usage: if (auto m = usage::decode(f)) {
            if (m->delayed) emit({{"t", "delivery"}, {"regime", "zero_credit"}, {"delay_ms", m->delay_ms}, {"unfunded_message_count", m->unfunded_message_count}, {"msg", m->notice}});
            emit({{"t", "usage"}, {"units", m->units}, {"balance", m->balance}, {"seq", m->seq}});
        } return;
        case code::payload: if (auto m = payload::decode(f)) {
            if (m->seq <= last_in_seq) return;                            // replayed after a resume: already read
            last_in_seq = m->seq;
            push({RelayEvent::Kind::binary, {}, {}, std::move(m->ciphertext)});
            std::lock_guard lk(mu);
            outq.push_front({std::vector<std::uint8_t>(), false});      // an ack, ahead of anything queued (encoded below)
            outq.front().bytes = std::vector<std::uint8_t>{'a', 'c', 'k'};
        } return;
        case code::referee_offer: if (auto m = referee_offer::decode(f)) emit({{"t", "referee_offer"}, {"on", m->on}, {"timeout_sec", m->timeout_sec}, {"from", m->from}}); return;
        case code::referee_pending: if (auto m = referee_pending::decode(f)) emit({{"t", "referee_pending"}, {"on", m->on}, {"timeout_sec", m->timeout_sec}}); return;
        case code::referee_mode: if (auto m = referee_mode::decode(f)) emit({{"t", "referee_mode"}, {"on", m->on}, {"timeout_sec", m->timeout_sec}}); return;
        case code::referee_declined: if (auto m = referee_declined::decode(f)) emit({{"t", "referee_declined"}, {"on", m->on}}); return;
        case code::round_ready: if (auto m = round_ready::decode(f)) emit({{"t", "round_ready"}, {"exchange_id", m->exchange_id}, {"round", m->round}, {"deadline", m->deadline}}); return;
        case code::commit_held: if (auto m = commit_held::decode(f)) emit({{"t", "commit_held"}, {"exchange_id", m->exchange_id}, {"round", m->round}, {"deadline", m->deadline}}); return;
        case code::reveal_held: if (auto m = reveal_held::decode(f)) emit({{"t", "reveal_held"}, {"exchange_id", m->exchange_id}, {"round", m->round}}); return;
        case code::release_held: if (auto m = release_held::decode(f)) emit({{"t", "release_held"}, {"exchange_id", m->exchange_id}, {"round", m->round}, {"delay_ms", m->delay_ms}}); return;
        case code::commits: if (auto m = commits::decode(f))
            emit({{"t", "commits"}, {"exchange_id", m->attestation.exchange_id}, {"phase", m->attestation.phase}, {"round", m->attestation.round},
                  {"mine", m->mine}, {"peer", m->peer}, {"peer_sig", nonzero(m->peer_signature) ? b64(m->peer_signature.data(), 64) : std::string{}},
                  {"receipt", receipt_json(m->attestation)}});
            return;
        case code::round_release: if (auto m = round_release::decode(f))
            emit({{"t", "round_release"}, {"exchange_id", m->attestation.exchange_id}, {"phase", m->attestation.phase}, {"round", m->attestation.round},
                  {"receipt", receipt_json(m->attestation)}});
            return;
        case code::round_expired: if (auto m = round_expired::decode(f)) emit({{"t", "round_expired"}, {"exchange_id", m->exchange_id}, {"round", m->round}, {"reason", m->reason}}); return;
        default: break;
        }
        if (info->code == link::invite_create_reply::k) {
            if (auto m = link::invite_create_reply::decode(f))
                emit({{"t", "invite"}, {"code", m->invite_code}, {"host_handle", m->host_handle}, {"billing", m->billing == link::invite_billing::split ? "split" : "host"},
                      {"expires", m->expires}, {"max_uses", m->max_uses}, {"share", m->share}});
            return;
        }
        if (info->code == link::ok_reply::k) { emit({{"t", "ok"}}); return; }
    }

    // ---- v4: the handshake, then the sealed stream ----
    template <class Ws> awaitable<void> pump_v4(Ws& ws) {
        ws.set_option(websocket::stream_base::timeout{std::chrono::seconds(30), std::chrono::seconds(30), true});
        ws.set_option(websocket::stream_base::decorator([](websocket::request_type& r) { r.set(beast::http::field::user_agent, "converge-bridge/0.2"); }));
        co_await ws.async_handshake(parsed.host + ":" + parsed.port, parsed.path, use_awaitable);
        std::optional<RelayClient::RelayKey> expected = get_relay_key ? get_relay_key() : std::nullopt;
        init.emplace(expected);
        out_seq = 0;
        auto m1 = init->hello({"call-keys-v3", "exchange-v3", "resume"});
        if (!m1) throw std::runtime_error("handshake: could not start");
        ws.binary(true);
        co_await ws.async_write(asio::buffer(*m1), use_awaitable);
        // The relay's v3 challenge (a text frame) comes first on a shared socket; it is not ours.
        beast::flat_buffer hb;
        std::string m2;
        for (;;) {
            hb.clear();
            co_await ws.async_read(hb, use_awaitable);
            if (ws.got_binary()) { m2 = beast::buffers_to_string(hb.data()); break; }
        }
        auto body = init->on_relay_hello(std::span<const std::uint8_t>(reinterpret_cast<const std::uint8_t*>(m2.data()), m2.size()));
        if (!body) {
            switch (body.error()) {
            case link::hs_error::static_key: throw std::runtime_error("the relay's key is not the one pinned for it; if the relay really changed its key, remove the relay: line from the pin store");
            case link::hs_error::confirm: throw std::runtime_error("the relay could not prove it holds its key");
            case link::hs_error::version: throw std::runtime_error("the relay speaks another protocol version");
            default: throw std::runtime_error("handshake failed");
            }
        }
        if (!expected && put_relay_key) put_relay_key(body->static_key);
        link::client_auth a;
        a.identity = creds.identity;
        auto pk = crypto::b64_decode(pub);
        if (!pk || pk->size() != 32) throw std::runtime_error("call key");
        std::copy(pk->begin(), pk->end(), a.call_key.begin());
        auto sig = creds.sign ? creds.sign(link::auth_text(body->domain, a.identity, init->transcript(), body->static_key)) : std::nullopt;
        auto bind = creds.sign ? creds.sign(link::call_key_binding_text(a.identity, a.call_key)) : std::nullopt;
        if (!sig || sig->size() != 64 || !bind || bind->size() != 64) throw std::runtime_error("identity signing failed (agent unavailable?)");
        std::copy(sig->begin(), sig->end(), a.signature.begin());
        std::copy(bind->begin(), bind->end(), a.call_key_signature.begin());
        a.want = static_cast<link::intent>(creds.intent);
        a.alias = creds.alias;
        a.invite_code = creds.invite_code;
        if (!session_id.empty()) { a.resume_session = session_id; a.resume_key = resume_key; a.last_seq_seen = last_in_seq; }
        for (const auto& line : creds.certificates) {
            // body, signer and signature, base64 each, tab separated: what the pairing page or the CLI hands over.
            const auto t1 = line.find('\t'), t2 = t1 == std::string::npos ? std::string::npos : line.find('\t', t1 + 1);
            if (t2 == std::string::npos) continue;
            auto b = crypto::b64_decode(line.substr(0, t1)), sg = crypto::b64_decode(line.substr(t1 + 1, t2 - t1 - 1)), si = crypto::b64_decode(line.substr(t2 + 1));
            if (!b || !sg || sg->size() != 32 || !si || si->size() != 64) continue;
            link::certificate c; c.body.assign(b->begin(), b->end());
            std::copy(sg->begin(), sg->end(), c.signer.begin()); std::copy(si->begin(), si->end(), c.signature.begin());
            a.certificates.push_back(std::move(c));
        }
        auto sealed = init->stream().seal(a.encode());
        if (!sealed) throw std::runtime_error("seal");
        co_await ws.async_write(asio::buffer(*sealed), use_awaitable);
        is_connected = true;

        auto ex = co_await asio::this_coro::executor;
        asio::steady_timer wake(ex);
        auto alive = std::make_shared<bool>(true);
        { std::lock_guard lk(mu); kick = [&wake] { wake.cancel(); }; }
        asio::co_spawn(ex, writer(ws, wake, alive), asio::detached);

        beast::flat_buffer buf;
        try {
            for (;;) {
                buf.clear();
                co_await ws.async_read(buf, use_awaitable);
                if (!ws.got_binary()) continue;
                auto* p = static_cast<const std::uint8_t*>(buf.data().data());
                auto opened = init->stream().open(std::span<const std::uint8_t>(p, buf.size()));
                if (!opened) { std::fprintf(stderr, "[converge-bridge] relay: a frame did not open; reconnecting\n"); break; }
                translate(*opened);
            }
        } catch (...) {}
        // What was queued stays queued: the session resumes and sends it, and the relay drops any
        // payload it already relayed by its sequence number.
        { std::lock_guard lk(mu); kick = nullptr; }
        *alive = false;
        wake.cancel();
        is_connected = false;
        asio::steady_timer t(ex, std::chrono::milliseconds(10));
        co_await t.async_wait(use_awaitable);
    }

    template <class Ws> awaitable<void> pump(Ws& ws) {
        // Keepalive: a WebSocket ping every 15 s of silence, and the connection is dead after 30 s
        // without any frame from the relay. Without this a relay that vanished (a cut network, a
        // sleeping laptop) was only noticed by a failed write, which on an idle connection is never.
        ws.set_option(websocket::stream_base::timeout{std::chrono::seconds(30), std::chrono::seconds(30), true});
        ws.set_option(websocket::stream_base::decorator([](websocket::request_type& r) {
            r.set(beast::http::field::user_agent, "converge-bridge/0.1");
        }));
        co_await ws.async_handshake(parsed.host + ":" + parsed.port, parsed.path, use_awaitable);

        // The relay speaks first with a challenge; identity auth signs it. A bearer-only
        // client could ignore it, but we always read it so the frame is not mistaken for
        // a control message later.
        std::string nonce;
        {
            beast::flat_buffer hb;
            co_await ws.async_read(hb, use_awaitable);
            try {
                auto v = json::parse(beast::buffers_to_string(hb.data()));
                if (v.is_object() && v.get_object().contains("nonce"))
                    nonce = std::string(v.get_object().at("nonce").as_string());
            } catch (...) {}
        }

        json::object hello{{"t", "hello"}, {"pub", pub}, {"v", 3},
                           {"features", json::array{"call-keys-v3", "exchange-v3"}}};
        if (creds.sign && !creds.handle.empty()) {
            auto sig = creds.sign(auth_challenge_message(nonce, creds.handle));
            if (!sig) throw std::runtime_error("identity signing failed (agent unavailable?)");
            hello["handle"] = creds.handle;
            hello["sig"] = crypto::b64_encode(sig->data(), sig->size());
            // Bind the ephemeral X25519 key to this identity so the peer can pin it.
            if (auto bs = creds.sign(session_binding_message(creds.handle, pub)))
                hello["pub_sig"] = crypto::b64_encode(bs->data(), bs->size());
        } else {
            hello["key"] = creds.key;
        }
        const std::string hello_frame = json::serialize(hello);
        ws.text(true);
        co_await ws.async_write(asio::buffer(hello_frame), use_awaitable);
        is_connected = true;

        auto ex = co_await asio::this_coro::executor;
        asio::steady_timer wake(ex);
        auto alive = std::make_shared<bool>(true);
        { std::lock_guard lk(mu); kick = [&wake] { wake.cancel(); }; }
        asio::co_spawn(ex, writer(ws, wake, alive), asio::detached);

        beast::flat_buffer buf;
        try {
            for (;;) {
                buf.clear();
                co_await ws.async_read(buf, use_awaitable);
                if (ws.got_text()) {
                    auto s = beast::buffers_to_string(buf.data());
                    std::string t;
                    try {
                        auto v = json::parse(s);
                        if (v.is_object())
                            if (auto* f = v.get_object().if_contains("t"); f && f->is_string())
                                t = std::string(f->get_string());
                    } catch (...) {}
                    if (t == "pong") continue;
                    push({RelayEvent::Kind::text, std::move(t), std::move(s), {}});
                } else {
                    auto* p = static_cast<const std::uint8_t*>(buf.data().data());
                    push({RelayEvent::Kind::binary, {}, {}, std::vector<std::uint8_t>(p, p + buf.size())});
                }
            }
        } catch (...) {}
        // Whatever was queued for this connection dies with it: a hangup or an accept meant for a
        // call that ended must not go out on the next connection, where it would name a call that
        // no longer exists.
        { std::lock_guard lk(mu); kick = nullptr; outq.clear(); }
        *alive = false;
        wake.cancel();
        is_connected = false;
        // give the writer a turn to observe `alive` before `wake`/`ws` go out of scope
        asio::steady_timer t(ex, std::chrono::milliseconds(10));
        co_await t.async_wait(use_awaitable);
    }

    awaitable<void> connect_loop() {
        int backoff = 1;
        while (running) {
            try {
                tcp::resolver res(io);
                auto eps = co_await res.async_resolve(parsed.host, parsed.port, use_awaitable);
                if (parsed.tls) {
                    websocket::stream<beast::ssl_stream<beast::tcp_stream>> ws(io, tls);
                    if (!SSL_set_tlsext_host_name(ws.next_layer().native_handle(), parsed.host.c_str()))
                        throw std::runtime_error("SNI");
                    // The certificate must be for the relay we asked for, not merely one some CA
                    // issued for anyone: without this check any CA-signed certificate passed, and a
                    // machine in the path could present its own and read the hello.
                    ws.next_layer().set_verify_callback(ssl::host_name_verification(parsed.host));
                    beast::get_lowest_layer(ws).expires_after(std::chrono::seconds(10));
                    co_await beast::get_lowest_layer(ws).async_connect(eps, use_awaitable);
                    beast::get_lowest_layer(ws).socket().set_option(tcp::no_delay(true));
                    co_await ws.next_layer().async_handshake(ssl::stream_base::client, use_awaitable);
                    beast::get_lowest_layer(ws).expires_never();   // from here the WebSocket timeouts apply
                    if (v4()) co_await pump_v4(ws); else co_await pump(ws);
                } else {
                    websocket::stream<beast::tcp_stream> ws(io);
                    beast::get_lowest_layer(ws).expires_after(std::chrono::seconds(10));
                    co_await beast::get_lowest_layer(ws).async_connect(eps, use_awaitable);
                    beast::get_lowest_layer(ws).socket().set_option(tcp::no_delay(true));
                    beast::get_lowest_layer(ws).expires_never();
                    if (v4()) co_await pump_v4(ws); else co_await pump(ws);
                }
                backoff = 1;
            } catch (const std::exception& e) {
                std::fprintf(stderr, "[converge-bridge] relay: %s\n", e.what());
            }
            is_connected = false;
            push({RelayEvent::Kind::disconnected, {}, {}, {}});
            if (!running) break;
            asio::steady_timer t(io, std::chrono::seconds(backoff));
            co_await t.async_wait(use_awaitable);
            backoff = std::min(backoff * 2, 30);
        }
    }
};

RelayClient::RelayClient(std::string url, Credentials creds, std::string pub_b64) : impl_(std::make_unique<Impl>()) {
    impl_->url = std::move(url); impl_->creds = std::move(creds); impl_->pub = std::move(pub_b64);
    auto p = parse_url(impl_->url);
    if (!p) throw std::runtime_error("bad relay url: " + impl_->url);
    impl_->parsed = *p;
    impl_->tls.set_default_verify_paths();
    impl_->tls.set_verify_mode(ssl::verify_peer);
}

RelayClient::~RelayClient() { stop(); }

void RelayClient::set_relay_key_store(std::function<std::optional<RelayKey>()> get, std::function<void(const RelayKey&)> put) {
    impl_->get_relay_key = std::move(get); impl_->put_relay_key = std::move(put);
}

void RelayClient::start() {
    impl_->running = true;
    impl_->thread = std::thread([this] {
        asio::co_spawn(impl_->io, impl_->connect_loop(), asio::detached);
        impl_->io.run();
    });
}

void RelayClient::stop() {
    if (!impl_->running.exchange(false)) return;
    impl_->io.stop();
    if (impl_->thread.joinable()) impl_->thread.join();
}

void RelayClient::send_binary(std::vector<std::uint8_t> f) {
    std::function<void()> k;
    { std::lock_guard lk(impl_->mu); impl_->outq.push_back({std::move(f), true}); k = impl_->kick; }
    if (k) asio::post(impl_->io, k);
}

void RelayClient::send_text(std::string s) {
    std::function<void()> k;
    { std::lock_guard lk(impl_->mu); impl_->outq.push_back({std::vector<std::uint8_t>(s.begin(), s.end()), false}); k = impl_->kick; }
    if (k) asio::post(impl_->io, k);
}

std::optional<RelayEvent> RelayClient::wait_event(int timeout_ms) {
    std::unique_lock lk(impl_->mu);
    if (!impl_->cv.wait_for(lk, std::chrono::milliseconds(timeout_ms), [&] { return !impl_->events.empty(); }))
        return std::nullopt;
    auto e = std::move(impl_->events.front());
    impl_->events.pop_front();
    return e;
}

bool RelayClient::connected() const { return impl_->is_connected; }

std::optional<RelayClient::Url> RelayClient::parse_url(const std::string& u) {
    Url r;
    std::string rest;
    if (u.starts_with("wss://")) { r.tls = true; rest = u.substr(6); }
    else if (u.starts_with("ws://")) { r.tls = false; rest = u.substr(5); }
    else return std::nullopt;
    auto slash = rest.find('/');
    std::string hp = rest.substr(0, slash);
    r.path = slash == std::string::npos ? "/v1/ws" : rest.substr(slash);
    auto colon = hp.rfind(':');
    if (colon != std::string::npos) { r.host = hp.substr(0, colon); r.port = hp.substr(colon + 1); }
    else { r.host = hp; r.port = r.tls ? "443" : "80"; }
    if (r.host.empty()) return std::nullopt;
    return r;
}

} // namespace converge
