// converge_session: the bridge side of the in-session interaction. ux::Session decides what the
// user sees and what may happen next; this file does the sending and the waiting it allows.
#include "mcp.hpp"

#include <algorithm>
#include <chrono>
#include <cstdlib>
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

std::string Bridge::live_ack_file() const {
    return platform::to_utf8(platform::from_utf8(live_dir()) / (std::to_string(platform::process_id()) + ".ack"));
}

// Once, at startup, before this bridge has produced a single display piece.
//
// Piece ids start at 1 in every process, so an ack file left behind by an earlier bridge that
// happened to have this pid names exactly the ids this one is about to hand out. Read, it would
// acknowledge displays that were never shown and drop them from the carry-forward, losing content
// silently, which is the one failure this design does not accept. So this bridge starts from its
// own empty file. The same pass is the lifecycle bound on the directory: it is cheap, it looks at
// nothing but CONVERGE's own "<pid>.ack" names in CONVERGE's own directory, it keeps every file a
// live process still owns, and any failure is ignored (an invocation must not depend on cleanup).
void Bridge::reset_live_state() {
    std::error_code ec;
    const std::filesystem::path dir(live_dir());
    platform::make_private_dir(dir);
    std::filesystem::remove(live_ack_file(), ec);
    ec.clear();
    std::filesystem::directory_iterator it(dir, std::filesystem::directory_options::skip_permission_denied, ec), end;
    for (int examined = 0; !ec && it != end && examined < 512; it.increment(ec), ++examined) {
        const auto name = it->path().filename().string();
        if (name.size() < 5 || !name.ends_with(".ack")) continue;
        const auto digits = name.substr(0, name.size() - 4);
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

ux::Context Bridge::session_context_locked() const {
    ux::Context c;
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
    auto finish = [&](json::object out) {
        out["in_call"] = in_call_;
        if (auto* live = out.if_contains("live"); live && live->is_object()) {
            std::error_code ec;
            platform::make_private_dir(std::filesystem::path(ack_file).parent_path());
            live->as_object()["ack"] = ack_file;
        }
        return out;
    };
    auto done = [&](const ux::Out& o) { return finish(ux_.to_json(o)); };


    if (action == "activate") {
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
        std::uint64_t converged = 0;
        for (const auto& [round, digest] : my_results_)
            if (auto it = peer_results_.find(round); it != peer_results_.end() && it->second == digest) converged = round;
        return done(ux_.conclude(arg_str(a, "outcome"), arg_str(a, "summary"), converged));
    }
    if (action == "exit") {
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
        const auto kind = arg_str(a, "kind", "answer");
        const auto round = static_cast<std::uint64_t>(std::max<std::int64_t>(arg_int(a, "round", 0), 0));
        // `guidance` stays here. Only kind, body and round travel, exactly as with converge_send.
        json::object env{{"kind", kind}, {"body", body}, {"round", round}, {"seq", ++seq_}, {"ts",
            std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count()}};
        json::object report;
        if (referee_) {
            // Under the barrier the peer's message for the same round comes back with the send.
            auto r = barriered_send(lk, std::move(env), false, 0, std::max(wait_s, 1)).as_object();
            if (!r.at("ok").as_bool()) { r["state"] = std::string(ux::name(ux_.state())); return r; }
            ux_.sent(body, kind, round, guidance, arg_str(r, "notice"));
            auto out = ux_.to_json(ux_.received({{arg_str(r, "peer_kind", "exchange"), arg_str(r, "peer_body"),
                                                  static_cast<std::uint64_t>(arg_int(r, "round", 0))}},
                                                session_context_locked()));
            out["speed"] = arg_str(r, "speed", "full");
            return finish(std::move(out));
        }
        std::string err;
        const auto acks = usage_acks_;
        if (!send_envelope(env, &err)) return refused(err);
        await_delivery_report(lk, acks, report);
        ux_.sent(body, kind, round, guidance, arg_str(report, "notice"));
        auto out = session_wait(lk, wait_s);
        out["speed"] = arg_str(report, "speed", "full");
        if (auto* d = report.if_contains("delay_sec")) out["delay_sec"] = *d;
        return finish(std::move(out));
    }

    return json::object{{"ok", false}, {"error", "action must be one of: activate, menu, status, account, help, choose, reply, "
                                                 "wait, need_input, conclude, transcript, interrupt, exit"}};
}

} // namespace converge
