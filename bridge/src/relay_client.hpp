#pragma once
#include <array>
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

// How this bridge authenticates to the relay: an Ed25519 identity, which is a Solana address.
// The handshake is sealed before the identity signs anything, the signature is bound to this
// relay's name and key, and the key is its own account until a certificate or an invitation
// says otherwise.
struct Credentials {
    std::string handle;   // informational; the handle is derived from the identity
    // Returns a raw 64-byte Ed25519 signature over the message, or nullopt.
    std::function<std::optional<std::vector<std::uint8_t>>(std::string_view)> sign;
    std::array<std::uint8_t, 32> identity{};   // the raw Ed25519 public key
    std::string alias;                          // for a key on its own, or an invitation's guest
    int intent = 0;                             // link::intent: 0 member, 1 redeem an invitation, 2 link one, 3 wait to be paired
    std::string invite_code;
    std::vector<std::string> certificates;      // certificate lines to present (body\tsigner\tsignature, base64 fields), if any
    std::string relay_key;                      // the relay's key (base58) given on the command line; else pinned on first use
};

// Owns a background io thread with one websocket connection to the relay.
// Reconnects with backoff until stop(). Thread-safe public API.
class RelayClient {
public:
    RelayClient(std::string url, Credentials creds, std::string pub_b64);
    ~RelayClient();

    // v4: the relay's static key this client expects (pinned on first use), and where to pin it.
    using RelayKey = std::array<std::uint8_t, 32>;
    void set_relay_key_store(std::function<std::optional<RelayKey>()> get, std::function<void(const RelayKey&)> put);

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
