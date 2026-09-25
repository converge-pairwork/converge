#include "fetch.hpp"

#include <boost/asio.hpp>
#include <boost/asio/ssl.hpp>
#include <boost/asio/ssl/host_name_verification.hpp>
#include <boost/beast.hpp>
#include <boost/beast/ssl.hpp>

#include <algorithm>
#include <cctype>
#include <chrono>

namespace converge::fetch {
namespace {
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http = beast::http;
namespace ssl = asio::ssl;
using tcp = asio::ip::tcp;

std::string lower(std::string_view s) {
    std::string out(s);
    std::transform(out.begin(), out.end(), out.begin(), [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return out;
}

// One exchange on one connection: the status, the body and, for a redirect, where to.
struct Reply { unsigned status = 0; std::string body, location; };

std::expected<Reply, std::string> once(const Url& u, const Options& options, ssl::context& tls) {
    asio::io_context io;
    tcp::resolver resolver(io);
    boost::system::error_code ec;
    auto endpoints = resolver.resolve(u.host, u.port, ec);
    if (ec) return std::unexpected("could not resolve " + u.host);
    http::request<http::string_body> req{options.body.empty() ? http::verb::get : http::verb::post, u.path, 11};
    req.set(http::field::host, u.host);
    req.set(http::field::user_agent, options.user_agent);
    req.set(http::field::accept, "application/octet-stream, application/json, text/plain, */*");
    if (!options.body.empty()) { req.set(http::field::content_type, "application/json"); req.body() = options.body; req.prepare_payload(); }
    http::response_parser<http::string_body> parser;
    parser.body_limit(options.limit + 1);
    beast::flat_buffer buffer;
    const auto step = std::chrono::seconds(options.timeout_sec);
    auto finish = [&](auto& stream) -> std::expected<Reply, std::string> {
        beast::get_lowest_layer(stream).expires_after(step);
        http::write(stream, req, ec);
        if (ec) return std::unexpected("could not send the request to " + u.host);
        beast::get_lowest_layer(stream).expires_after(step * 4);
        http::read(stream, buffer, parser, ec);
        if (ec == http::error::body_limit) return std::unexpected("the response is too large");
        if (ec) return std::unexpected("could not read the response from " + u.host);
        Reply r;
        r.status = parser.get().result_int();
        r.body = std::move(parser.get().body());
        if (auto it = parser.get().find(http::field::location); it != parser.get().end()) r.location = std::string(it->value());
        return r;
    };
    if (u.tls) {
        beast::ssl_stream<beast::tcp_stream> stream(io, tls);
        if (!SSL_set_tlsext_host_name(stream.native_handle(), u.host.c_str())) return std::unexpected("could not name the host for TLS");
        stream.set_verify_callback(ssl::host_name_verification(u.host));
        beast::get_lowest_layer(stream).expires_after(step);
        beast::get_lowest_layer(stream).connect(endpoints, ec);
        if (ec) return std::unexpected("could not connect to " + u.host);
        beast::get_lowest_layer(stream).expires_after(step);
        stream.handshake(ssl::stream_base::client, ec);
        if (ec) return std::unexpected("TLS to " + u.host + " failed: " + ec.message());
        auto r = finish(stream);
        beast::get_lowest_layer(stream).expires_after(std::chrono::seconds(2));
        stream.shutdown(ec);
        return r;
    }
    beast::tcp_stream stream(io);
    stream.expires_after(step);
    stream.connect(endpoints, ec);
    if (ec) return std::unexpected("could not connect to " + u.host);
    auto r = finish(stream);
    stream.socket().shutdown(tcp::socket::shutdown_both, ec);
    return r;
}
} // namespace

std::expected<Url, std::string> parse_url(std::string_view url) {
    Url u;
    std::string_view rest;
    if (url.starts_with("https://")) { u.tls = true; rest = url.substr(8); }
    else if (url.starts_with("http://")) { u.tls = false; rest = url.substr(7); }
    else return std::unexpected("not an http(s) URL");
    const auto slash = rest.find('/');
    std::string_view authority = rest.substr(0, slash);
    u.path = slash == std::string_view::npos ? "/" : std::string(rest.substr(slash));
    if (authority.find('@') != std::string_view::npos) return std::unexpected("a URL with credentials is not fetched");
    const auto colon = authority.rfind(':');
    if (colon != std::string_view::npos && authority.find(']') == std::string_view::npos) {
        u.host = std::string(authority.substr(0, colon));
        u.port = std::string(authority.substr(colon + 1));
        if (u.port.empty() || u.port.find_first_not_of("0123456789") != std::string::npos) return std::unexpected("bad port");
    } else {
        u.host = std::string(authority);
        u.port = u.tls ? "443" : "80";
    }
    if (u.host.empty()) return std::unexpected("no host");
    u.host = lower(u.host);
    return u;
}

bool host_allowed(std::string_view base_url, std::string_view host) {
    auto base = parse_url(base_url);
    if (!base) return false;
    const auto h = lower(host);
    if (h == base->host) return true;
    if (base->host == "github.com" || base->host.ends_with(".github.com"))
        return h == "github.com" || h == "objects.githubusercontent.com" || h == "release-assets.githubusercontent.com" ||
               h == "raw.githubusercontent.com";
    return false;
}

std::expected<std::string, std::string> get(std::string_view url, const Options& options) {
    ssl::context tls{ssl::context::tls_client};
    tls.set_default_verify_paths();
    tls.set_verify_mode(ssl::verify_peer);
    std::string current(url);
    const auto origin = parse_url(url);
    if (!origin) return std::unexpected(origin.error());
    for (int hop = 0; hop <= options.max_redirects; ++hop) {
        auto u = parse_url(current);
        if (!u) return std::unexpected(u.error());
        // A plain-HTTP local development source may stay on plain HTTP; anything that started
        // on HTTPS must still be on HTTPS at the end of the chain.
        if (origin->tls && !u->tls) return std::unexpected("the source redirected off HTTPS");
        if (!host_allowed(url, u->host)) return std::unexpected("the source redirected to an unexpected host");
        try {
            auto r = once(*u, options, tls);
            if (!r) return std::unexpected(r.error());
            if (r->status >= 300 && r->status < 400 && !r->location.empty()) {
                if (r->location.starts_with("/")) current = std::string(u->tls ? "https://" : "http://") + u->host + (u->port == (u->tls ? "443" : "80") ? "" : ":" + u->port) + r->location;
                else current = r->location;
                continue;
            }
            if (r->status < 200 || r->status >= 300) return std::unexpected("HTTP " + std::to_string(r->status) + " from " + u->host);
            if (r->body.size() > options.limit) return std::unexpected("the response is too large");
            return std::move(r->body);
        } catch (const std::exception& e) {
            return std::unexpected(std::string("fetch failed: ") + e.what());
        }
    }
    return std::unexpected("too many redirects");
}

} // namespace converge::fetch
