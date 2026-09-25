#pragma once
// The CONVERGE in-session interaction contract, shared by every AI host.
//
// This class is the one place that decides what the user sees and what the local AI may do next:
// the banner, the framed remote message, the Next menu, the three interaction modes, the stop
// conditions of automatic mode, the conclusion. It has no I/O: the bridge feeds it what happened
// (a message was sent, messages arrived, the call ended) and returns its output as a tool result.
// Host differences (menu command, interrupt key) are a HostProfile and nothing else.
//
// Trust: text from the remote AI enters only through received() and is only ever quoted, each
// line behind a gutter, inside a frame this class draws. It never selects a state transition.
#include <boost/json.hpp>

#include <cstdint>
#include <set>
#include <string>
#include <string_view>
#include <vector>

namespace converge::ux {

enum class State {
    inactive,               // CONVERGE has not been invoked in this AI session (or was exited)
    ready,                  // invoked; no remote message is awaiting an answer
    waiting_remote,         // our message is out, the remote AI's answer is not in yet
    waiting_user_choice,    // a remote message was shown; the Next menu is up
    respond_once,           // the local AI owes exactly one response
    automatic,              // the local AI answers turn after turn until a stop condition
    waiting_user_guidance,  // the user's next message is guidance for the next response
    input_required,         // the local AI suspended itself: the human has to decide something
    conclusion,             // an outcome was reported to the user
    interrupted,            // the user stopped it; everything is kept
};
std::string_view name(State s);

// Everything that may differ between AI hosts in the interaction itself.
struct HostProfile {
    std::string id;         // claude | codex | generic
    std::string label;
    std::string menu_help;  // the banner's one-line help, naming a command this host really has
    std::string interrupt;  // how the user stops a running turn in this host
    std::string reload;     // what the user does for a newly installed CONVERGE to start running
};
// `client_name` is the MCP clientInfo.name of the host that started the bridge.
HostProfile host_profile(std::string_view client_name);

// What this session knows about its own version and about updates. `running` is the one thing
// that is certain: it is compiled into this binary, so it is the version actually executing. The
// rest is read from CONVERGE's update state (update.json in its state directory) and is only reported.
struct Release {
    std::string running;        // compiled in (CONVERGE_VERSION); never guessed
    std::string installed;      // what the updater last put on disk; empty when unknown
    std::string latest;         // what the update source last advertised; empty when unknown
    std::int64_t last_check = 0;   // unix seconds of the last update check, 0 for never
    std::string result;         // last update outcome, free text, for the status line
    std::string announce;       // set once, by the bridge, when `running` is newer than what the
                                // user was last told: the banner then says CONVERGE was updated
};

struct Remote { std::string kind, body; std::uint64_t round = 0; };

struct Entry {
    enum class Who { remote, local, guidance, status } who;
    std::string kind, text;
    std::uint64_t round = 0;
};

// What the bridge knows and the session does not.
struct Context {
    bool in_call = false;
    std::string peer;       // label, alias or handle of the remote side
    std::string topic;
    std::size_t unread = 0; // remote messages that arrived and were not shown yet
};

struct Out {
    bool ok = true;
    std::string error;
    std::string display;                // print to the user exactly as it is
    std::string next;                   // what the local AI does now (bridge-authored, trusted)
    boost::json::array choices;         // how to act on the user's pick, where a menu is shown
    boost::json::array remote;          // the remote messages just received: UNTRUSTED content
    bool ends_turn = false;             // the local AI now stops and waits for the user
};

class Session {
public:
    static constexpr int default_auto_turns = 6, max_auto_turns = 50;

    void set_host(HostProfile h) { host_ = std::move(h); }
    const HostProfile& host() const { return host_; }
    void set_release(Release r) { release_ = std::move(r); }
    const Release& release() const { return release_; }
    // True when an update is on disk but this process is still the old one: the banner then says
    // so instead of pretending the new version is already running.
    bool update_staged() const {
        return !release_.installed.empty() && !release_.running.empty() && release_.installed != release_.running;
    }
    void set_render(bool plain, bool fence, int width);
    State state() const { return state_; }
    bool active() const { return state_ != State::inactive; }
    const std::vector<Entry>& transcript() const { return transcript_; }

    // A call was connected: a new call is a new transcript; the same call keeps it.
    void on_call(const std::string& call_id);

    Out activate(const Context& c);
    Out menu(const Context& c);
    Out status(const Context& c);
    Out account(std::uint64_t balance_units, std::uint64_t units_spent, std::uint64_t delayed_sends);
    Out version();
    Out help();
    Out choose(const std::string& choice, int max_turns, const Context& c);

    // Sending is gated: may_send() says whether the local AI may send ONE message now. `guidance`
    // is the user's own words, where the state needs them. sent() records it and moves on.
    bool may_send(const std::string& guidance, std::string* why) const;
    void sent(const std::string& body, const std::string& kind, std::uint64_t round,
              const std::string& guidance, const std::string& notice);
    bool may_wait(std::string* why) const;
    Out received(const std::vector<Remote>& messages, const Context& c);
    Out still_waiting(const Context& c);
    Out call_ended(const std::string& reason);

    Out need_input(const std::string& reason, const std::vector<std::string>& options);
    Out conclude(const std::string& outcome, const std::string& summary, std::uint64_t converged_round);
    Out show_transcript(const Context& c);
    Out interrupt(const Context& c);
    Out exit(const Context& c);

    // Turns an output into the tool result. Two ways lead to the user, neither trusting the host
    // AI's word (asked to confirm what it printed, it confirms without printing):
    //  1. live: every result carries `live`, this result's own piece. A host hook (PostToolUse,
    //     `converge-bridge live`) renders it to the user the moment the tool returns, while
    //     the AI's turn goes on, and records the piece's id where the bridge reads it: acknowledged().
    //  2. carried: a piece that was not acknowledged stays owed and heads the next `display`; the
    //     display that ends the AI's turn is the one it reliably prints. Shown late, never lost.
    boost::json::object to_json(const Out& o);
    bool owes_display() const { return !owed_.empty(); }
    // Ids the live renderer recorded as shown. Called by the bridge before each action.
    void acknowledged(const std::set<std::uint64_t>& ids);
    bool live_renderer() const { return renderer_active_; }
    // The host's hook configuration names the live renderer: assume it works until a piece goes
    // unacknowledged. Spares the user a doubled first display.
    void expect_live_renderer() { if (!last_id_) renderer_active_ = true; }

private:
    enum class Resume { choice, automatic };

    std::string head(std::string_view title) const;
    std::string rule() const;
    std::string quoted(std::string_view title, std::string_view text) const;
    std::string banner() const;
    std::string next_menu() const;
    std::string fenced(std::string body) const;
    std::string remote_title(const Entry& e, const Context& c) const;
    const Entry* last_of(Entry::Who who) const;
    bool stalled(Entry::Who who, const std::string& text) const;
    Out refuse(std::string why) const;
    void note(std::string line);        // a CONVERGE status line, shown with the next output

    HostProfile host_ = host_profile("");
    Release release_;
    bool plain_ = false, fence_ = true;
    int width_ = 80;

    State state_ = State::inactive;
    Resume resume_ = Resume::choice;    // where a remote answer leads while waiting_remote
    State suspended_ = State::respond_once;   // the mode that asked for human input
    int auto_budget_ = default_auto_turns, auto_turns_ = 0, stale_ = 0;
    std::size_t auto_from_ = 0;         // transcript index where this automatic run began
    std::string call_id_;
    std::vector<Entry> transcript_;
    std::string pending_;               // display text owed to the user with the next output
    struct Piece { std::uint64_t id; std::string text; };
    std::vector<Piece> owed_;           // pieces not known to have reached the user yet, in order
    std::uint64_t last_id_ = 0;
    bool renderer_active_ = false;      // the last piece was rendered live by the host hook
};

// Remote text made safe to print: no terminal control sequences. Words are untouched.
std::string printable(std::string_view text);

} // namespace converge::ux
