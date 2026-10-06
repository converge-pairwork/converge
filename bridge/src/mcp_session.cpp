// converge_session: the bridge side of the in-session interaction. ux::Session decides what the
// user sees and what may happen next; this file does the sending and the waiting it allows.
#include "mcp.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <set>
#include <string>
#include <vector>

#include "platform.hpp"

namespace converge {

namespace json = boost::json;

namespace {
std::string arg_str(const json::object& o, std::string_view k, std::string def = "") {
    if (auto* v = o.if_contains(k); v && v->is_string()) return std::string(v->get_string());
    return def;
}
std::int64_t arg_int(const json::object& o, std::string_view k, std::int64_t def) {
    if (auto* v = o.if_contains(k); v && v->is_number()) return v->to_number<std::int64_t>();
    return def;
}
// Block characters need a UTF-8 terminal. CONVERGE_PLAIN=1 forces the ASCII rendering.
bool plain_by_default() {
    if (const char* p = std::getenv("CONVERGE_PLAIN"); p && *p && *p != '0') return true;
    for (const char* name : {"LC_ALL", "LC_CTYPE", "LANG"}) {
        const char* v = std::getenv(name);
        if (!v || !*v) continue;
        std::string s(v);
        std::transform(s.begin(), s.end(), s.begin(), [](unsigned char c) { return std::tolower(c); });
        return s.find("utf-8") == std::string::npos && s.find("utf8") == std::string::npos;
    }
    return false;
}
} // namespace

// ---- version and updates -------------------------------------------------------------------------
// CONVERGE_VERSION is stamped in by the build from the repository's VERSION file. It is the only
// version this process can state as fact: it is the code that is running. Everything else comes
// from the updater's state file and is reported as what it is.
#ifndef CONVERGE_VERSION
#define CONVERGE_VERSION "0.0.0"
#endif

namespace {
// A version string we are willing to print: MAJOR.MINOR.PATCH and nothing else. Anything the
// updater's state file holds that is not that shape is treated as unknown.
bool plain_version(std::string_view v) {
    int groups = 0, digits = 0;
    for (const char c : v) {
        if (c == '.') { if (!digits || ++groups > 2) return false; digits = 0; }
        else if (c >= '0' && c <= '9') { if (++digits > 9) return false; }
        else return false;
    }
    return groups == 2 && digits > 0;
}
} // namespace

std::string Bridge::state_dir() const {
    return platform::to_utf8(platform::from_utf8(history_file_).parent_path());
}

// update.json in CONVERGE's state directory (platform.hpp), written by the updater
// (`converge-bridge update`, tools.cpp) and only read here. Nothing in it decides anything: it fills in the version screen. A missing, unreadable or
// nonsensical file leaves the fields empty, which the screen says plainly.
ux::Release Bridge::read_release() const {
    ux::Release r;
    r.running = CONVERGE_VERSION;
    std::ifstream in(platform::from_utf8(state_dir()) / "update.json");
    if (in) {
        try {
            const std::string text((std::istreambuf_iterator<char>(in)), {});
            const auto doc = json::parse(text).as_object();
            const auto str = [&](std::string_view k) -> std::string {
                auto* v = doc.if_contains(k);
                if (!v || !v->is_string()) return {};
                std::string out(v->get_string());
                return out.size() <= 64 ? out : std::string();
            };
            r.installed = plain_version(str("installed_version")) ? str("installed_version") : std::string();
            r.latest = plain_version(str("latest_known_version")) ? str("latest_known_version") : std::string();
            r.result = str("last_result");
            if (auto* v = doc.if_contains("last_update_check"); v && v->is_number())
                r.last_check = v->to_number<std::int64_t>();
        } catch (...) {
            // Update state is advisory. An unreadable file must never keep CONVERGE from starting.
        }
    }
    // What the user was last told they were running. The first run records it and says nothing;
    // a later run whose code is a different version is the one that announces the update.
    const auto stamp = platform::from_utf8(state_dir()) / "announced_version";
    std::string told;
    { std::ifstream f(stamp); std::getline(f, told); }
    while (!told.empty() && (told.back() == '\n' || told.back() == '\r' || told.back() == ' ')) told.pop_back();
    if (!told.empty() && told != r.running && plain_version(told)) r.announce = r.running;
    if (told != r.running) {
        std::error_code ec;
        std::filesystem::create_directories(stamp.parent_path(), ec);
        const auto temporary = stamp.parent_path() / (stamp.filename().string() + ".tmp");
        { std::ofstream out(temporary, std::ios::trunc); out << r.running << '\n'; }
        std::filesystem::rename(temporary, stamp, ec);
        if (ec) std::filesystem::remove(temporary, ec);
    }
    return r;
}

// `hooks_added` in the state directory: the AI clients a bridge registered the hold with after an
// update (tools.cpp, adopt_hold_hook), one id to a line. Read once and removed: the user is told
// in the banner of this invocation, and not again.
std::string Bridge::take_hooks_notice() const {
    const auto path = platform::from_utf8(state_dir()) / "hooks_added";
    std::error_code ec;
    if (std::filesystem::is_symlink(path, ec) || !std::filesystem::is_regular_file(path, ec)) return {};
    std::string names;
    bool codex = false;
    {
        std::ifstream in(path);
        for (std::string id; std::getline(in, id);) {
            const std::string name = id == "claude" ? "Claude Code" : id == "codex" ? "Codex" : "";
            if (name.empty()) continue;
            codex = codex || id == "codex";
            names += (names.empty() ? "" : " and ") + name;
        }
    }
    std::filesystem::remove(path, ec);
    if (names.empty()) return {};
    return "CONVERGE registered a hook with " + names + ": when your AI has nothing left to do but wait for the other side of a "
           "call, its turn is kept open and it carries on when their message arrives. It does nothing outside a CONVERGE call, and "
           "it starts with your next session." + (codex ? " Codex asks you to review it first (/hooks)." : "") +
           " To remove it: converge-bridge setup --remove-live-hook";
}

// Asks the updater to run. It is this same executable, started again as a separate short-lived
// process (`converge-bridge update`): it holds the hourly throttle, the download, the signature
// and digest checks and the atomic install. CONVERGE never depends on its outcome, which is the
// whole of C3: an update that cannot happen is not a CONVERGE failure.
//
// `wait_sec` 0 is the automatic check on invocation: started detached, never waited for. The
// manual "check for updates now" waits a few seconds so the screen it returns to can show the
// answer, and gives up on the wait (not on the updater) when that runs out.
void Bridge::request_update_check(bool forced, int wait_sec) const {
    std::vector<std::string> args{"update", "--check", "--state-dir", state_dir()};
    if (forced) args.push_back("--force");
    platform::run_self_detached(args, wait_sec);
}

// ---- live rendering state: the "live" directory of CONVERGE's state ------------------------------
// One "<pid>.ack" per running bridge. The host's live renderer (`converge-bridge live`)
// appends the id of every display piece it showed; ux::Session reads them and stops carrying those
// pieces forward. The path is built here, from this process's own pid and CONVERGE's own state
// directory: nothing a remote party sends ever names a file.
std::string Bridge::live_dir() const {
    return platform::to_utf8(platform::from_utf8(history_file_).parent_path() / "live");
}

std::string Bridge::live_file(const char* extension) const {
    return platform::to_utf8(platform::from_utf8(live_dir()) / (std::to_string(platform::process_id()) + extension));
}

std::string Bridge::live_ack_file() const { return live_file(".ack"); }

// ---- the hold: what the host's Stop hook is told ------------------------------------------------
// Nothing wakes an idle AI session, so a turn that ends while the other side is to write leaves
// the call unattended. The hook (`converge-bridge hold`) reads "<pid>.wait" when the AI tries to
// end its turn, holds the turn while `expects` says so, and hands the AI one line when something
// arrives. The file says what is awaited and never what was said: no message text, no name, no key.
//   remote  in a call, and the next thing is the other side's message
//   join    an invitation made in this session is out, and nobody has joined it yet
//   ""      nothing: the user's move, or this AI's own
std::string Bridge::wait_expects_locked() const {
    // The user left CONVERGE (Exit): the session is theirs again, and a turn that ends is not
    // held for a message or for someone joining, until CONVERGE is used again.
    if (left_) return {};
    if (in_call_) {
        const auto state = ux_.state();
        if (state == ux::State::waiting_remote) return "remote";
        // A result this side proposed for a round the other side has not proposed for yet: its
        // digest is what comes next, whatever the mode, unless the move is the user's.
        const bool users_move = state == ux::State::waiting_user_choice || state == ux::State::waiting_user_guidance ||
                                state == ux::State::input_required || state == ux::State::conclusion || state == ux::State::interrupted;
        if (!users_move && !my_results_.empty() && !peer_results_.contains(my_results_.rbegin()->first)) return "remote";
        // Connected and nothing sent from here: the caller opens (its turn ends for its user's
        // brief, not for the other side), anyone else waits for the opening.
        if (state == ux::State::ready && (role_ != "caller" || !ux_.transcript().empty() || !inbox_.empty())) return "remote";
        return {};
    }
    return invite_hold_until_ > static_cast<std::int64_t>(std::time(nullptr)) ? "join" : "";
}

void Bridge::publish_wait_locked() {
    const auto text = json::serialize(json::object{
        {"expects", wait_expects_locked()}, {"call", in_call_ ? call_id_ : std::string()},
        {"unread", inbox_.size()}, {"seq", inbound_count_},
        // Connected, and no tool result has said so yet: the AI does not know it is in a call.
        {"announce", in_call_ && announced_call_ != call_id_},
        // What was awaited cannot happen (an invitation lost, the inviter gone): how many times so far.
        {"notice", notice_.empty() ? std::uint64_t{0} : notice_count_}});
    if (text == wait_published_) return;
    const std::filesystem::path path(platform::from_utf8(live_file(".wait")));
    const auto temporary = path.parent_path() / (path.filename().string() + ".tmp");
    std::error_code ec;
    {
        std::ofstream out(temporary, std::ios::trunc);
        if (!out) return;
        out << text << '\n';
        if (!out.flush()) { out.close(); std::filesystem::remove(temporary, ec); return; }
    }
    std::filesystem::rename(temporary, path, ec);
    if (ec) { std::filesystem::remove(temporary, ec); return; }
    wait_published_ = text;
}

// The hook leaves "<pid>.hold" the first time it runs for this bridge: the proof that this host
// runs it (Codex runs a hook only once the user has reviewed it).
bool Bridge::hold_seen() const {
    std::error_code ec;
    const std::filesystem::path path(platform::from_utf8(live_file(".hold")));
    return !std::filesystem::is_symlink(path, ec) && std::filesystem::is_regular_file(path, ec);
}

// Once, at startup, before this bridge has produced a single display piece.
//
// Piece ids start at 1 in every process, so an ack file left behind by an earlier bridge that
// happened to have this pid names exactly the ids this one is about to hand out. Read, it would
// acknowledge displays that were never shown and drop them from the carry-forward, losing content
// silently, which is the one failure this design does not accept. So this bridge starts from its
// own empty file. The same pass is the lifecycle bound on the directory: it is cheap, it looks at
// nothing but CONVERGE's own "<pid>.ack" names (and .wait, .session, .hold) in CONVERGE's own directory, it keeps every file a
// live process still owns, and any failure is ignored (an invocation must not depend on cleanup).
void Bridge::reset_live_state() {
    std::error_code ec;
    const std::filesystem::path dir(live_dir());
    platform::make_private_dir(dir);
    for (const char* extension : {".ack", ".wait", ".session", ".hold"}) std::filesystem::remove(live_file(extension), ec);
    ec.clear();
    std::filesystem::directory_iterator it(dir, std::filesystem::directory_options::skip_permission_denied, ec), end;
    for (int examined = 0; !ec && it != end && examined < 512; it.increment(ec), ++examined) {
        const auto name = it->path().filename().string();
        const auto dot = name.rfind('.');
        if (dot == std::string::npos || dot == 0) continue;
        const auto extension = name.substr(dot);
        if (extension != ".ack" && extension != ".wait" && extension != ".session" && extension != ".hold") continue;
        const auto digits = name.substr(0, dot);
        if (digits.find_first_not_of("0123456789") != std::string::npos) continue;
        std::error_code one;
        if (std::filesystem::is_symlink(it->path(), one) || !std::filesystem::is_regular_file(it->path(), one)) continue;
        const auto pid = std::strtoul(digits.c_str(), nullptr, 10);
        // Only a process id nobody holds is cleaned up: "not sure" has to mean "leave it".
        if (platform::process_alive(pid)) continue;
        std::filesystem::remove(it->path(), one);
    }
}

// What the renderer recorded since the last call. A file that is not a plain file of ours (a
// symlink, a directory) is not read at all; an unreadable one simply acknowledges nothing, and the
// pieces stay owed. Uncertainty here shows a display twice; it never drops one.
std::set<std::uint64_t> Bridge::read_acknowledged() const {
    std::set<std::uint64_t> ids;
    const auto path = live_ack_file();
    std::error_code ec;
    if (std::filesystem::is_symlink(path, ec) || !std::filesystem::is_regular_file(path, ec)) return ids;
    std::ifstream in(path);
    for (std::uint64_t id; in >> id;) ids.insert(id);
    return ids;
}

// The name this user gave the peer, saved on this machine only, when `body` uses it as a word
// ("" when it does not, or the peer has no such name). A message to the other side addresses its
// reader; this user's name for them is not theirs to receive.
std::string Bridge::local_label_in_locked(const std::string& body) const {
    std::string label;
    for (const auto& item : connections_)
        if (item.is_object() && arg_str(item.as_object(), "handle") == peer_handle_) { label = arg_str(item.as_object(), "label"); break; }
    if (label.empty() || label == peer_handle_ || label.size() < 2) return {};
    auto lower = [](std::string s) { for (auto& ch : s) ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch))); return s; };
    const auto text = lower(body), word = lower(label);
    auto letter = [](char ch) { return std::isalnum(static_cast<unsigned char>(ch)) || (static_cast<unsigned char>(ch) & 0x80); };
    for (auto at = text.find(word); at != std::string::npos; at = text.find(word, at + 1)) {
        const bool starts = at == 0 || !letter(text[at - 1]);
        const bool ends = at + word.size() >= text.size() || !letter(text[at + word.size()]);
        if (starts && ends) return label;
    }
    return {};
}

ux::Context Bridge::session_context_locked() const {
    ux::Context c;
    c.me = name_;
    c.in_call = in_call_;
    c.topic = call_topic_;
    c.unread = inbox_.size();
    c.peer = peer_alias_.empty() ? peer_handle_ : peer_alias_;
    for (const auto& item : connections_) {
        if (!item.is_object()) continue;
        const auto& o = item.as_object();
        auto* h = o.if_contains("handle");
        auto* l = o.if_contains("label");
        if (h && h->is_string() && h->get_string() == peer_handle_ && l && l->is_string() && !l->get_string().empty())
            c.peer = std::string(l->get_string());
    }
    return c;
}

// Waits for the remote AI and hands whatever arrived to the session, which shows all of it.
json::object Bridge::session_wait(std::unique_lock<std::mutex>& lk, int wait_s) {
    inbox_cv_.wait_for(lk, std::chrono::seconds(wait_s), [&] { return !inbox_.empty() || stop_ || !in_call_; });
    std::vector<ux::Remote> got;
    while (!inbox_.empty() && got.size() < 10) {
        auto& m = inbox_.front();
        got.push_back({m.kind, m.body, m.round});
        inbox_.pop_front();
    }
    const auto c = session_context_locked();
    if (!got.empty()) return ux_.to_json(ux_.received(got, c));
    if (!in_call_) return ux_.to_json(ux_.call_ended(last_error_.starts_with("call ended: ") ? last_error_.substr(12) : ""));
    return ux_.to_json(ux_.still_waiting(c));
}

json::value Bridge::t_session(const json::object& a) {
    const auto action = arg_str(a, "action");
    const int wait_s = static_cast<int>(std::clamp<std::int64_t>(arg_int(a, "wait_sec", 45), 0, 50));
    std::unique_lock lk(mu_);
    // What the host's live renderer recorded as shown since the last call (see session_ux.hpp).
    const auto ack_file = live_ack_file();
    ux_.acknowledged(read_acknowledged());
    // Whether a turn that ends now is held and resumed: the hook runs here, and the other side is to write.
    ux_.set_held(hold_expected() && wait_expects_locked() == "remote");
    auto finish = [&](json::object out) {
        out["in_call"] = in_call_;
        // What each remote message is measured against (agent/skill.md, Keep to the topic).
        if (out.contains("remote_untrusted"))
            out["topic"] = call_topic_.empty() ? std::string("not set: the brief the user gave is the topic") : call_topic_;
        if (auto* live = out.if_contains("live"); live && live->is_object()) {
            std::error_code ec;
            platform::make_private_dir(std::filesystem::path(ack_file).parent_path());
            live->as_object()["ack"] = ack_file;
        }
        return out;
    };
    auto done = [&](const ux::Out& o) { return finish(ux_.to_json(o)); };


    if (action == "activate") {
        left_ = false;
        if (!ux_.active()) {
            if (auto host = arg_str(a, "host"); !host.empty()) ux_.set_host(ux::host_profile(host));
            const char* cols = std::getenv("COLUMNS");
            const auto* plain = a.if_contains("plain");
            const auto* fence = a.if_contains("fence");
            ux_.set_render(plain && plain->is_bool() ? plain->get_bool() : plain_by_default(),
                           fence && fence->is_bool() ? fence->get_bool() : true,
                           static_cast<int>(arg_int(a, "width", cols && std::atoi(cols) > 0 ? std::atoi(cols) : 80)));
        }
        // The version actually executing, and whatever the updater has left behind. Then ask it to
        // check: it decides by its own persistent throttle whether that means contacting anything.
        ux_.set_release(read_release());
        if (!ux_.active()) if (auto notice = take_hooks_notice(); !notice.empty()) ux_.set_notice(std::move(notice));
        request_update_check(false, 0);
        // Host adapter: where this host keeps its hooks. Both Claude Code and Codex put theirs
        // under the user's home on every platform they support, Windows included, so this is one
        // rule rather than three (platform::home() is what knows how to find that home).
        if (!ux_.active()) {
            const auto& host = ux_.host().id;
            const std::filesystem::path dir = host == "claude" ? ".claude" : host == "codex" ? ".codex" : "";
            const std::string name = host == "claude" ? "settings.json" : "hooks.json";
            std::ifstream in(dir.empty() ? std::filesystem::path() : platform::home() / dir / name);
            const std::string text((std::istreambuf_iterator<char>(in)), {});
            // The hook is registered on CONVERGE's own tool name; the command is this bridge's
            // `live` subcommand today and was the Python renderer before client 0.2.0.
            if (text.find("mcp__converge__converge_session") != std::string::npos) ux_.expect_live_renderer();
            // The hold, registered as a Stop hook: Claude Code runs it from the first turn on, so the
            // AI is told to end its turn from the first wait, not only once the hook has been seen.
            if (host == "claude" && text.find("\"Stop\"") != std::string::npos && text.find("converge-bridge") != std::string::npos &&
                text.find("hold") != std::string::npos) hold_registered_ = true;
        }
        auto out = done(ux_.activate(session_context_locked()));
        out["connected"] = relay_.connected();
        out["host"] = ux_.host().id;
        return out;
    }
    if (action == "menu") return done(ux_.menu(session_context_locked()));
    if (action == "status") return done(ux_.status(session_context_locked()));
    if (action == "account") return done(ux_.account(balance_, units_spent_, delayed_sends_));
    if (action == "version") { ux_.set_release(read_release()); return done(ux_.version()); }
    if (action == "update") {
        // The one path that bypasses the hourly throttle, and only because the user asked for it.
        request_update_check(true, 10);
        auto r = read_release();
        r.announce.clear();
        ux_.set_release(std::move(r));
        auto out = done(ux_.version());
        return out;
    }
    if (action == "help") return done(ux_.help());
    if (action == "name") {
        // The user's name as CONVERGE writes it for them: the opening of every invitation.
        const auto given = ux::one_line(arg_str(a, "name"), 60);
        json::object out;
        if (given.empty()) {
            out["display"] = "Your name in CONVERGE: " + (name_.empty() ? std::string("not set") : ux::printable(name_)) + "\n";
            out["next"] = "Ask the user what name to use, then call converge_session(action: \"name\", name: \"<their answer>\").";
        } else {
            name_ = given;
            save_local_history();
            out["display"] = "Your name in CONVERGE is now " + ux::printable(name_) + ". Invitations open with it.\n";
            out["next"] = "Show `display`.";
        }
        out["ok"] = true;
        out["name"] = name_;
        return finish(std::move(out));
    }
    if (action == "transcript") return done(ux_.show_transcript(session_context_locked()));
    if (action == "interrupt") return done(ux_.interrupt(session_context_locked()));
    if (action == "choose")
        return done(ux_.choose(arg_str(a, "choice"), static_cast<int>(arg_int(a, "max_turns", 0)), session_context_locked()));

    if (action == "need_input") {
        std::vector<std::string> options;
        if (auto* v = a.if_contains("options"); v && v->is_array())
            for (const auto& o : v->get_array())
                if (o.is_string()) options.emplace_back(o.get_string());
        return done(ux_.need_input(arg_str(a, "reason"), options));
    }
    if (action == "conclude") {
        std::optional<std::uint64_t> converged;
        for (const auto& [round, digest] : my_results_)
            if (auto it = peer_results_.find(round); it != peer_results_.end() && it->second == digest) converged = round;
        auto concluded = ux_.conclude(arg_str(a, "outcome"), arg_str(a, "summary"), converged);
        // An outcome is on disk before anyone closes anything: the call's folder, as it stands now.
        if (in_call_) store_session_locked(session_record_locked(0));
        return done(std::move(concluded));
    }
    if (action == "exit") {
        if (ux_.active()) { left_ = true; invite_hold_until_ = 0; }
        const auto* h = a.if_contains("hangup");
        if (h && h->is_bool() && h->get_bool() && ux_.active() && (in_call_ || !dialing_.empty())) {
            relay_.send_text(json::serialize(json::object{{"t", "hangup"}, {"call_id", in_call_ ? call_id_ : dialing_}}));
            end_call();
        }
        return done(ux_.exit(session_context_locked()));
    }

    if (action == "wait") {
        std::string why;
        if (!ux_.may_wait(&why)) return json::object{{"ok", false}, {"state", std::string(ux::name(ux_.state()))}, {"error", why}};
        return finish(session_wait(lk, wait_s));
    }

    if (action == "reply") {
        const auto body = arg_str(a, "body");
        const auto guidance = arg_str(a, "guidance");
        std::string why;
        auto refused = [&](std::string e) {
            return json::object{{"ok", false}, {"state", std::string(ux::name(ux_.state()))}, {"error", std::move(e)}};
        };
        if (!ux_.may_send(guidance, &why)) return refused(why);
        if (body.empty()) return refused("pass `body`: the message your AI wrote for the remote AI");
        if (!in_call_ || !sealer_) return refused("not in a call: use converge_call, or accept an incoming one");
        if (const auto label = local_label_in_locked(body); !label.empty())
            return refused("not sent: the message names the other side \"" + label + "\", which is what your user calls them on this "
                           "machine and not theirs to receive. Write to its reader: \"you\", \"your side\", \"your user\"; then reply again.");
        const auto kind = arg_str(a, "kind", "answer");
        const auto round = static_cast<std::uint64_t>(std::max<std::int64_t>(arg_int(a, "round", 0), 0));
        // `guidance` stays here. Only kind, body and round travel, exactly as with converge_send.
        json::object env{{"kind", kind}, {"body", body}, {"round", round}, {"seq", ++seq_}, {"ts",
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()}};
        json::object report;
        std::string err;
        const auto acks = usage_acks_;
        if (!send_envelope(env, &err)) return refused(err);
        await_delivery_report(lk, acks, report);
        ux_.sent(body, kind, round, guidance, arg_str(report, "notice"), session_context_locked());
        auto out = session_wait(lk, wait_s);
        out["speed"] = arg_str(report, "speed", "full");
        if (auto* d = report.if_contains("delay_sec")) out["delay_sec"] = *d;
        return finish(std::move(out));
    }

    return json::object{{"ok", false}, {"error", "action must be one of: activate, menu, status, account, help, choose, reply, "
                                                 "wait, need_input, conclude, transcript, interrupt, exit"}};
}

} // namespace converge
