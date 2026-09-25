// One HTTP GET, for the release files the bridge installs and updates itself with, and for the
// skill it installs. Synchronous, bounded in time and in size, and it follows a redirect only to
// a host the caller allows: a release on github.com hands its bytes to a github-owned host, and
// a redirect anywhere else is an error rather than a download. TLS verification is the default
// and is never relaxed; a download that starts on https stays on https.
#pragma once
#include <cstddef>
#include <expected>
#include <functional>
#include <string>
#include <string_view>

namespace converge::fetch {

struct Url { bool tls = false; std::string host, port, path; };
std::expected<Url, std::string> parse_url(std::string_view url);

// The hosts a download that starts at `base` may finish on: the base's own host, and for a
// github.com release the hosts github keeps release assets on. Nothing a manifest, a server
// or a setting says can add to this set.
bool host_allowed(std::string_view base_url, std::string_view host);

struct Options {
    std::size_t limit = 64 * 1024 * 1024;   // a body larger than this is an error, not a download
    int timeout_sec = 8;                    // per connection step; the whole GET is bounded by a few of these
    int max_redirects = 5;
    std::string user_agent = "converge-bridge";
    std::string body;                       // non-empty: a POST of application/json
};

// The response body of a 2xx, or why there is none.
std::expected<std::string, std::string> get(std::string_view url, const Options& options = {});

} // namespace converge::fetch
