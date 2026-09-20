#include "relay_client.hpp"

#include "crypto.hpp"
#include "identity.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/websocket/ssl.hpp>
#include <boost/json.hpp>

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
                ws.binary(o->binary);
                co_await ws.async_write(asio::buffer(o->bytes), use_awaitable);
            }
        } catch (...) {}
    }

    template <class Ws> awaitable<void> pump(Ws& ws) {
        ws.set_option(websocket::stream_base::timeout::suggested(beast::role_type::client));
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
        if (!creds.gateway.empty()) {
            hello["handle"] = creds.handle;
            hello["gateway"] = creds.gateway;
        } else if (creds.sign && !creds.handle.empty()) {
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
        { std::lock_guard lk(mu); kick = nullptr; }
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
                    co_await beast::get_lowest_layer(ws).async_connect(eps, use_awaitable);
                    co_await ws.next_layer().async_handshake(ssl::stream_base::client, use_awaitable);
                    co_await pump(ws);
                } else {
                    websocket::stream<beast::tcp_stream> ws(io);
                    co_await beast::get_lowest_layer(ws).async_connect(eps, use_awaitable);
                    co_await pump(ws);
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
