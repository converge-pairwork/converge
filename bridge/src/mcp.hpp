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

struct PendingCall {
    std::string id, from, from_alias;
    std::int64_t ts = 0;
};

// Holds relay state + the E2E session for the current call, and serves MCP over stdio.
class Bridge {
public:
    Bridge(std::string relay_url, Credentials creds, std::string pin_store, std::string identity_line = {});
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
    boost::json::value t_join(const boost::json::object& a);
    boost::json::value t_confirm(const boost::json::object& a);
    boost::json::value t_fingerprint();
    boost::json::value t_billing(const boost::json::object& a);
    // The in-session interaction (banner, framed remote messages, Next menu, modes): session_ux.hpp
    // decides, this sends and waits. Defined in mcp_session.cpp.
    boost::json::value t_session(const boost::json::object& a);
    boost::json::object session_wait(std::unique_lock<std::mutex>& lk, int wait_s);
    ux::Context session_context_locked() const;
    std::string local_label_in_locked(const std::string& body) const;
    // The live-rendering handshake with the host hook (`converge-bridge live`).
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
    std::string id_line_;          // this member's identity public key, if any
    RelayClient relay_;
    std::thread reactor_thread_;
    bool stop_ = false;

    mutable std::mutex mu_;
    std::condition_variable inbox_cv_, call_cv_;
    std::string handle_, alias_, last_error_, auth_mode_;
    std::string pairing_link_;     // while this key is its own account: the link that adds it to a wallet's (welcome)
    std::string wallet_;           // the Solana address of the wallet whose account this bridge is on ("" = its own)
    bool relay_away_ = false;              // v4: the socket dropped mid call; the session may resume

    // Peer pinning (trust on first use). Maps a peer handle to the identity key it used.
    std::string pin_store_;
    std::string relay_url_;        // for converge_join, which joins on a connection of its own
    Credentials creds_;
    std::string history_file_;
    std::string name_;             // the user's own name for what the bridge writes for them (connections.json)
    // What the user calls the people they invited, kept here and never sent: {code, name, expires}.
    // The first call from a new peer that the relay accepted for an invitation takes the name, when
    // exactly one is waiting (connections.json).
    boost::json::array invite_names_;
    std::set<std::string> invited_calls_;   // incoming calls the relay accepted for an invitation
    std::map<std::string, std::string> pins_;
    void load_pins();
    void save_pin(const std::string& handle, const std::string& pubkey);
    std::uint64_t balance_ = 0, units_spent_ = 0, seq_ = 0;
    // Each payload frame is answered by `usage`: what this account was charged, and whether it goes out late.
    std::uint64_t usage_acks_ = 0, delayed_sends_ = 0, last_delay_ms_ = 0;
    bool last_delayed_ = false;
    std::condition_variable usage_cv_;
    void await_delivery_report(std::unique_lock<std::mutex>& lk, std::uint64_t acks_before, boost::json::object& out);

    // Who pays (the relay's `terms` and `delivery` for the current call; empty outside one), the
    // peer's open "you pay" proposal, the peer's answer to ours, and this bridge's preferences as
    // the relay last stated them. Nothing here is ever sent to the peer.
    boost::json::object terms_, delivery_, billing_prefs_;
    std::optional<boost::json::object> billing_request_;
    std::optional<bool> billing_answer_;
    std::uint64_t billing_prefs_seq_ = 0, terms_seq_ = 0;
    std::condition_variable billing_cv_;
    // What was last told to the AI about the terms and the delivery, so a change is told once.
    std::string told_terms_, told_delivery_, told_request_;
    boost::json::object payment_locked() const;                      // caller holds mu_
    boost::json::array advice_locked() const;                        // caller holds mu_: what would lift a delay
    // The same, as one line: about the message just sent, or (`sent` false) about this call's
    // messages before any is sent. Caller holds mu_.
    std::string delay_notice_locked(bool sent = true) const;
    void payment_notes_locked(boost::json::object& out);             // caller holds mu_
    std::string site_url() const;

    // call state
    std::string call_id_, peer_handle_, peer_alias_, peer_pub_b64_, role_, dialing_;
    std::string peer_identity_, peer_trust_;      // peer_trust_: unauthenticated|new|pinned|CHANGED
    bool in_call_ = false;
    std::set<std::string> used_call_ids_;  // process lifetime: refuse key/nonce reuse
    std::vector<PendingCall> pending_;
    std::optional<crypto::Sealer> sealer_;

    std::deque<InboundMessage> inbox_;
    boost::json::value invite_;                   // last invite minted, awaited by t_invite
    std::condition_variable invite_cv_;
    boost::json::array result_rounds_locked() const;
    boost::json::array completed_calls_;  // Last ten calls, process-local; never written to the relay.
    boost::json::array connections_;      // Local labels and known peers for this member.
    boost::json::array past_sessions_;    // Local call history; never sent to the relay.
    std::int64_t call_started_at_ = 0;
    std::string dialing_topic_, call_topic_;
    bool placing_call_ = false;    // converge_call is dialing: a `calling` now is ours, not the relay's for an invitation
    std::map<std::uint64_t, std::string> my_result_text_;
    std::map<std::uint64_t, std::string> my_results_, peer_results_;   // round -> digest
    ux::Session ux_;                      // interaction state of this AI session; guarded by mu_
};

} // namespace converge
