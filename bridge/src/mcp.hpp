#pragma once
#include "crypto.hpp"
#include "identity.hpp"
#include "relay_client.hpp"
#include "session_ux.hpp"

#include <boost/json.hpp>

#include <functional>

#include <condition_variable>
#include <cstdint>
#include <deque>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <string>
#include <thread>
#include <vector>

namespace converge {

struct InboundMessage {
    std::string kind, body, digest;
    std::uint64_t round = 0;
    std::int64_t ts = 0;
};

// One refereed exchange in flight. The bridge drives commit -> reveal and verifies that
// the peer's revealed bytes match the commitment it was bound to.
struct ExchangeState {
    std::string id;
    std::string my_commit, peer_commit, peer_sig;
    boost::json::value receipt;
    bool commits_released = false, released = false, expired = false;
    bool signature_verified = false;
    std::string error;
    std::string peer_body, peer_kind;
    std::int64_t peer_score = 0;
    bool peer_scored = false;
    std::uint64_t round = 0;
    std::int64_t release_delay_ms = 0;   // the relay completed the round and releases it this much later
};

// The relay's word on a message the account's usage credit did not cover: accepted, and it arrives late. `notice` is
// for the user of this session only and is never put into anything sent to the peer.
struct DelayedDelivery { std::uint64_t delay_ms = 0, unfunded_message_count = 0; std::string notice; };

struct PendingCall {
    std::string id, from, from_alias;
    bool same_account = false;
    std::int64_t ts = 0;
};

// Holds relay state + the E2E session for the current call, and serves MCP over stdio.
class Bridge {
public:
    using Signer = std::function<std::optional<std::vector<std::uint8_t>>(std::string_view)>;
    Bridge(std::string relay_url, Credentials creds, std::string pin_store,
           std::string identity_line = {}, Signer signer = {});
    ~Bridge();
    int serve_stdio();           // blocks until stdin closes

private:
    // MCP plumbing
    boost::json::value handle(const boost::json::object& req);
    boost::json::object tools_list() const;
    boost::json::value call_tool(const std::string& name, const boost::json::object& args);
    static boost::json::object text_result(const boost::json::value& v, bool is_error = false);

    // tools
    boost::json::value t_status();
    boost::json::value t_call(const boost::json::object& a);
    boost::json::value t_connections();
    boost::json::value t_set_connection_label(const boost::json::object& a);
    boost::json::value t_sessions();
    boost::json::value t_calls(const boost::json::object& args);
    boost::json::value t_accept(const boost::json::object& a);
    boost::json::value t_reject(const boost::json::object& a);
    boost::json::value t_hangup();
    boost::json::value t_send(const boost::json::object& a);
    boost::json::value t_receive(const boost::json::object& a);
    boost::json::value t_propose_result(const boost::json::object& a);
    boost::json::value t_invite(const boost::json::object& a);
    boost::json::value t_referee(const boost::json::object& a);
    boost::json::value t_referee_respond(const boost::json::object&, bool accept);
    // Sends one message under the barrier: commit, wait, reveal, wait. Caller holds mu_.
    boost::json::value barriered_send(std::unique_lock<std::mutex>& lk, boost::json::object env,
                                      bool have_score, std::int64_t score, int wait_s);
    boost::json::value t_fingerprint();
    // The in-session interaction (banner, framed remote messages, Next menu, modes): session_ux.hpp
    // decides, this sends and waits. Defined in mcp_session.cpp.
    boost::json::value t_session(const boost::json::object& a);
    boost::json::object session_wait(std::unique_lock<std::mutex>& lk, int wait_s);
    ux::Context session_context_locked() const;
    // The live-rendering handshake with the host hook (site/agent/converge-live.py).
    std::string state_dir() const;
    ux::Release read_release() const;
    void request_update_check(bool forced, int wait_sec) const;
    std::string live_dir() const;
    std::string live_ack_file() const;
    void reset_live_state();
    std::set<std::uint64_t> read_acknowledged() const;

    // relay event reactor (background thread)
    void reactor();
    void on_connected(const boost::json::object& o);      // caller holds mu_
    void end_call();                                      // caller holds mu_
    void load_local_history();
    void save_local_history();                             // caller holds mu_
    bool send_envelope(const boost::json::object& env, std::string* err);
    boost::json::value status_locked();                   // caller holds mu_

    crypto::Identity id_;
    Signer signer_;
    std::string id_line_;          // this member's identity public key, if any
    RelayClient relay_;
    std::thread reactor_thread_;
    bool stop_ = false;

    mutable std::mutex mu_;
    std::condition_variable inbox_cv_, call_cv_;
    std::string handle_, alias_, account_, policy_, last_error_, auth_mode_;
    bool auto_accept_ = false;

    // Peer pinning (trust on first use). Maps a peer handle to the identity key it used.
    std::string pin_store_;
    std::string history_file_;
    std::map<std::string, std::string> pins_;
    void load_pins();
    void save_pin(const std::string& handle, const std::string& pubkey);
    std::uint64_t balance_ = 0, units_spent_ = 0, seq_ = 0;
    // Each payload frame is answered by `usage`, preceded by `delivery` when it is delivered late.
    std::uint64_t usage_acks_ = 0, delayed_sends_ = 0;
    std::optional<DelayedDelivery> pending_delivery_, last_delivery_;
    std::condition_variable usage_cv_;
    void await_delivery_report(std::unique_lock<std::mutex>& lk, std::uint64_t acks_before, boost::json::object& out);

    // call state
    std::string call_id_, peer_handle_, peer_alias_, peer_pub_b64_, role_, dialing_;
    std::string peer_identity_, peer_trust_;      // peer_trust_: unauthenticated|new|pinned|CHANGED
    bool in_call_ = false;
    std::set<std::string> used_call_ids_;  // process lifetime: refuse key/nonce reuse
    std::vector<PendingCall> pending_;
    std::optional<crypto::Sealer> sealer_;

    std::deque<InboundMessage> inbox_;
    std::condition_variable exch_cv_;
    std::optional<ExchangeState> exch_;
    bool referee_ = false;                        // off by default: instant delivery
    int referee_timeout_ = 120;
    bool mode_pending_ = false, mode_offered_ = false, mode_declined_ = false;
    bool mode_offer_on_ = false;
    std::string peer_identity_key_;
    boost::json::value invite_;                   // last invite minted, awaited by t_invite
    std::condition_variable invite_cv_;               // peer's identity line, for verifying commitments
    std::int64_t last_score_sum_ = 0;
    bool have_last_score_ = false;
    std::uint64_t stalled_rounds_ = 0;
    boost::json::array result_rounds_locked() const;
    boost::json::array completed_calls_;  // Last ten calls, process-local; never written to the relay.
    boost::json::array connections_;      // Local labels and known peers for this member.
    boost::json::array past_sessions_;    // Local call history; never sent to the relay.
    std::int64_t call_started_at_ = 0;
    std::string dialing_topic_, call_topic_;
    std::map<std::uint64_t, std::string> my_result_text_;
    std::map<std::uint64_t, std::string> my_results_, peer_results_;   // round -> digest
    ux::Session ux_;                      // interaction state of this AI session; guarded by mu_
};

} // namespace converge
