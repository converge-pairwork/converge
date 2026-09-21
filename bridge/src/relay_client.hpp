#pragma once
#include <condition_variable>
#include <cstdint>
#include <deque>
#include <functional>
#include <memory>
#include <mutex>
#include <optional>
#include <string>
#include <thread>
#include <vector>

namespace converge {

struct RelayEvent {
    enum class Kind { text, binary, disconnected } kind;
    std::string t;                    // "t" field of a text frame (welcome, incoming, ...)
    std::string json;                 // raw text frame
    std::vector<std::uint8_t> bytes;  // binary payload
};

// How this bridge authenticates to the relay. Either a bearer key, or a handle plus a
// signature over the relay's challenge (in which case the relay holds no secret at all).
struct Credentials {
    std::string key;      // bearer secret, or empty
    std::string handle;   // required for identity auth
    // Returns a raw 64-byte Ed25519 signature over the message, or nullopt.
    std::function<std::optional<std::vector<std::uint8_t>>(std::string_view)> sign;
};

// Owns a background io thread with one websocket connection to the relay.
// Reconnects with backoff until stop(). Thread-safe public API.
class RelayClient {
public:
    RelayClient(std::string url, Credentials creds, std::string pub_b64);
    ~RelayClient();

    void start();
    void stop();
    void send_binary(std::vector<std::uint8_t> frame);
    void send_text(std::string json);

    // Blocks up to timeout_ms for an event; nullopt on timeout.
    std::optional<RelayEvent> wait_event(int timeout_ms);
    bool connected() const;

    struct Url { bool tls; std::string host, port, path; };
    static std::optional<Url> parse_url(const std::string& u);

private:
    struct Impl;
    std::unique_ptr<Impl> impl_;
};

} // namespace converge
