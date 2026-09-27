#include "tools.hpp"

#include "crypto.hpp"
#include "fetch.hpp"
#include "handshake.hpp"
#include "identity.hpp"
#include "platform.hpp"
#include "relay_client.hpp"
#include "release_key.hpp"
#include "session_ux.hpp"

#include <boost/json.hpp>

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iterator>
#include <map>
#include <optional>
#include <set>
#include <stdexcept>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

namespace converge::tools {
namespace json = boost::json;
namespace fs = std::filesystem;

namespace {

// Two sources, deliberately kept apart. The CONVERGE service holds accounts, balances and
// negotiations; the public source repository publishes the client software. Everything setup
// installs comes from a release of the second, verified against that release's own signed
// manifest; only the account questions go to the first.
constexpr const char* kDefaultBase = "https://converge.pairwork.net";
constexpr const char* kDefaultRelease = "https://github.com/converge-pairwork/converge/releases/latest/download";

// The same two environment variables install.sh reads, as the defaults when no option and no
// saved setup names them: a development lab points both at itself (a local relay and a release
// it signed with its own key, CONVERGE_RELEASE_KEY) and the unchanged guide then works there.
std::string default_base() {
    const char* v = std::getenv("CONVERGE_BASE");
    return v && *v ? v : kDefaultBase;
}
std::string default_release() {
    const char* v = std::getenv("CONVERGE_RELEASE_BASE");
    return v && *v ? v : kDefaultRelease;
}
constexpr const char* kHookMatcher = "mcp__converge__converge_session";

struct Failure : std::runtime_error { using std::runtime_error::runtime_error; };

// ---- small helpers -----------------------------------------------------------------------

std::string read_file(const fs::path& path) {
    std::ifstream in(path, std::ios::binary);
    if (!in) throw Failure("cannot read " + platform::to_utf8(path));
    return std::string((std::istreambuf_iterator<char>(in)), {});
}

std::optional<std::string> read_file_if(const fs::path& path) {
    std::error_code ec;
    if (!fs::is_regular_file(path, ec)) return std::nullopt;
    std::ifstream in(path, std::ios::binary);
    if (!in) return std::nullopt;
    return std::string((std::istreambuf_iterator<char>(in)), {});
}

// Atomic, private, and complete or not at all: a half-written state file would make the next
// run lie.
void write_private(const fs::path& path, std::string_view text) {
    platform::make_private_dir(path.parent_path());
    const auto temporary = path.parent_path() / ("." + platform::to_utf8(path.filename()) + ".tmp" + std::to_string(platform::process_id()));
    {
        std::ofstream out(temporary, std::ios::binary | std::ios::trunc);
        if (!out) throw Failure("cannot write " + platform::to_utf8(path));
        out.write(text.data(), static_cast<std::streamsize>(text.size()));
    }
    platform::make_private_file(temporary);
    std::error_code ec;
    fs::rename(temporary, path, ec);
    if (ec) { fs::remove(temporary, ec); throw Failure("cannot replace " + platform::to_utf8(path)); }
}

// JSON, written the way a person reads it: two-space indent, one trailing newline.
void pretty_into(std::string& out, const json::value& v, int depth, bool sorted) {
    const std::string pad(static_cast<std::size_t>(depth) * 2, ' '), inner(static_cast<std::size_t>(depth + 1) * 2, ' ');
    if (v.is_object()) {
        const auto& o = v.as_object();
        if (o.empty()) { out += "{}"; return; }
        std::vector<std::string_view> keys;
        for (const auto& kv : o) keys.push_back(kv.key());
        if (sorted) std::sort(keys.begin(), keys.end());
        out += "{\n";
        for (std::size_t i = 0; i < keys.size(); ++i) {
            out += inner + json::serialize(json::string(keys[i])) + ": ";
            pretty_into(out, o.at(keys[i]), depth + 1, sorted);
            out += i + 1 < keys.size() ? ",\n" : "\n";
        }
        out += pad + "}";
        return;
    }
    if (v.is_array()) {
        const auto& a = v.as_array();
        if (a.empty()) { out += "[]"; return; }
        out += "[\n";
        for (std::size_t i = 0; i < a.size(); ++i) {
            out += inner;
            pretty_into(out, a[i], depth + 1, sorted);
            out += i + 1 < a.size() ? ",\n" : "\n";
        }
        out += pad + "]";
        return;
    }
    out += json::serialize(v);
}

std::string pretty(const json::value& v, bool sorted = false) {
    std::string out;
    pretty_into(out, v, 0, sorted);
    return out + "\n";
}

std::optional<json::value> parse_json(std::string_view text) {
    boost::system::error_code ec;
    auto v = json::parse(text, ec);
    if (ec) return std::nullopt;
    return v;
}

json::object read_json_object(const fs::path& path) {
    auto text = read_file_if(path);
    if (!text) return {};
    auto v = parse_json(*text);
    return v && v->is_object() ? v->as_object() : json::object{};
}

std::string str(const json::object& o, std::string_view key) {
    auto* v = o.if_contains(key);
    return v && v->is_string() ? std::string(v->get_string()) : std::string();
}

bool has(const json::object& o, std::string_view key) { return o.contains(key); }

// A JSON text that names the same key twice in one object. A parser keeps one of the two, and
// two parsers need not agree which, so a manifest written that way is refused rather than read.
bool has_duplicate_keys(std::string_view text) {
    std::vector<std::optional<std::set<std::string>>> stack;   // one set per open object; nullopt for an array
    std::size_t i = 0;
    auto read_string = [&](std::string& out) -> bool {
        ++i;   // the opening quote
        while (i < text.size()) {
            const char c = text[i++];
            if (c == '"') return true;
            if (c == '\\' && i < text.size()) { out += c; out += text[i++]; continue; }
            out += c;
        }
        return false;
    };
    while (i < text.size()) {
        const char c = text[i];
        if (c == '{') { stack.emplace_back(std::set<std::string>{}); ++i; continue; }
        if (c == '[') { stack.emplace_back(std::nullopt); ++i; continue; }
        if (c == '}' || c == ']') { if (!stack.empty()) stack.pop_back(); ++i; continue; }
        if (c == '"') {
            std::string s;
            if (!read_string(s)) return false;
            std::size_t j = i;
            while (j < text.size() && (text[j] == ' ' || text[j] == '\t' || text[j] == '\n' || text[j] == '\r')) ++j;
            if (j < text.size() && text[j] == ':' && !stack.empty() && stack.back()) {
                if (!stack.back()->insert(s).second) return true;
            }
            continue;
        }
        ++i;
    }
    return false;
}

std::string hex_sha256(std::string_view data) {
    const auto d = crypto::sha256(data);
    return crypto::hex(d.data(), d.size());
}

struct Semver { long major = 0, minor = 0, patch = 0; auto operator<=>(const Semver&) const = default; };

// (major, minor, patch), or nullopt when it is not a plain MAJOR.MINOR.PATCH. Compared as
// numbers, so 0.10.0 is newer than 0.9.0 and no string ordering can say otherwise.
std::optional<Semver> semver(std::string_view text) {
    while (!text.empty() && (text.back() == ' ' || text.back() == '\n' || text.back() == '\r' || text.back() == '\t')) text.remove_suffix(1);
    while (!text.empty() && (text.front() == ' ' || text.front() == '\t')) text.remove_prefix(1);
    long parts[3];
    std::size_t pos = 0;
    for (int k = 0; k < 3; ++k) {
        std::size_t digits = 0;
        long value = 0;
        while (pos < text.size() && text[pos] >= '0' && text[pos] <= '9' && digits < 9) { value = value * 10 + (text[pos] - '0'); ++pos; ++digits; }
        if (digits == 0) return std::nullopt;
        parts[k] = value;
        if (k < 2) { if (pos >= text.size() || text[pos] != '.') return std::nullopt; ++pos; }
    }
    if (pos != text.size()) return std::nullopt;
    return Semver{parts[0], parts[1], parts[2]};
}

std::string semver_text(const Semver& v) { return std::to_string(v.major) + "." + std::to_string(v.minor) + "." + std::to_string(v.patch); }

// The version the downloaded SKILL.md states. One authoritative string travels with the skill;
// the bridge carries the same one compiled in, and that is the one that is executing.
std::string skill_version_of(std::string_view text) {
    const auto end = text.find("\n---\n");
    const auto head = text.substr(0, end);
    std::size_t start = 0;
    while (start <= head.size()) {
        const auto stop = head.find('\n', start);
        const auto line = head.substr(start, stop == std::string_view::npos ? std::string_view::npos : stop - start);
        if (line.starts_with("version:")) {
            auto value = line.substr(8);
            while (!value.empty() && value.front() == ' ') value.remove_prefix(1);
            while (!value.empty() && (value.back() == ' ' || value.back() == '\r')) value.remove_suffix(1);
            return semver(value) ? std::string(value) : std::string();
        }
        if (stop == std::string_view::npos) break;
        start = stop + 1;
    }
    return {};
}

bool valid_skill(std::string_view text) {
    return text.starts_with("---\nname: converge\n") && text.size() > 4 && text.substr(4).find("\n---\n") != std::string_view::npos;
}

std::int64_t now_seconds() { return static_cast<std::int64_t>(std::time(nullptr)); }

std::string arg_value(const std::vector<std::string>& args, std::size_t& i, const std::string& flag) {
    if (i + 1 >= args.size()) throw Failure(flag + " needs a value");
    return args[++i];
}

fs::path resolve_dir(const std::string& text) {
    std::error_code ec;
    auto p = fs::absolute(platform::from_utf8(text), ec);
    auto canonical = fs::weakly_canonical(p, ec);
    return ec ? p : canonical;
}

// ---- release verification: the manifest and its signature ----------------------------------

// Is this exactly the manifest CONVERGE published? The signature covers the manifest bytes as
// served, so a manifest that has been re-serialised, re-ordered or edited by one byte does not
// verify, whoever served it. The keys are compiled in (release_key.hpp).
//
// CONVERGE_RELEASE_KEY, when set, replaces them for this process. It is how the client's own
// test suite exercises this code with a key whose private half a test can hold; the production
// key's is the owner's and is on no machine that runs tests. It is not a weakening: whoever sets
// the updater's environment already runs code as this user and could replace the binary outright.
std::vector<std::string> release_keys() {
    if (const char* forced = std::getenv("CONVERGE_RELEASE_KEY"); forced && *forced) return {forced};
    std::vector<std::string> out;
    for (const char* k : release::keys) out.emplace_back(k);
    return out;
}

bool signed_by_converge(std::string_view manifest, std::string_view signature_text) {
    std::string token;
    for (const char c : signature_text) { if (c == ' ' || c == '\n' || c == '\r' || c == '\t') { if (!token.empty()) break; continue; } token += c; }
    auto sig = crypto::b64_decode(token);
    if (!sig || sig->size() != 64) return false;
    link::sig64 s{};
    std::copy(sig->begin(), sig->end(), s.begin());
    for (const auto& key : release_keys()) {
        auto raw = crypto::b64_decode(key);
        // A raw Ed25519 public key is 32 bytes. Anything else is not a key that could have signed
        // anything, and is skipped rather than fed to the verifier.
        if (!raw || raw->size() != 32) continue;
        link::key32 pub{};
        std::copy(raw->begin(), raw->end(), pub.begin());
        if (link::crypto::ed25519_verify(pub, manifest, s)) return true;
    }
    return false;
}

constexpr int kManifestSchema = 2;
constexpr std::size_t kMaxManifest = 256 * 1024;
constexpr std::size_t kMaxFile = 64 * 1024 * 1024;

struct Described { std::string path, sha256; std::optional<std::int64_t> size; };

// A manifest names files by a path under the release, never by a URL: the release source is
// the one this installation was set up with, and the manifest cannot move it.
bool plain_release_path(std::string_view path) {
    if (path.empty() || path.size() > 512) return false;
    std::size_t start = 0;
    while (start <= path.size()) {
        const auto stop = path.find('/', start);
        const auto part = path.substr(start, stop == std::string_view::npos ? std::string_view::npos : stop - start);
        if (part.empty() || part == "..") return false;
        for (const char c : part)
            if (!((c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9') || c == '.' || c == '_' || c == '-')) return false;
        if (stop == std::string_view::npos) break;
        start = stop + 1;
    }
    return true;
}

bool plain_sha256(std::string_view s) {
    return s.size() == 64 && std::all_of(s.begin(), s.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

// path, digest and size, each checked for shape before any of it is used.
Described described(std::string_view key, const json::object& item, int schema) {
    Described d;
    d.path = str(item, "path");
    d.sha256 = str(item, "sha256");
    if (!plain_release_path(d.path)) throw Failure("manifest path for " + std::string(key) + " is not a plain path under the origin");
    if (!plain_sha256(d.sha256)) throw Failure("manifest digest for " + std::string(key) + " is not a SHA-256");
    auto* size = item.if_contains("size");
    if (!size) {
        if (schema < 2) return d;   // the first manifests stated no size; for those there is nothing to check
        throw Failure("manifest size for " + std::string(key) + " is not a byte count");
    }
    if (!size->is_int64() || size->as_int64() <= 0) throw Failure("manifest size for " + std::string(key) + " is not a byte count");
    d.size = size->as_int64();
    return d;
}

struct NoBridgeHere : Failure { using Failure::Failure; };

// The manifest's description of one file, validated down to its shape before use. A bridge is
// per platform: the manifest describes them under `bridge`, keyed by operating system and
// architecture, and this picks the entry for the machine this is running on and nothing else.
Described entry(const json::object& manifest, std::string_view key, int schema) {
    if (key == "bridge") {
        auto* binaries = manifest.if_contains("bridge");
        if (binaries && binaries->is_object()) {
            const std::string here = platform::release_platform();
            if (here.empty()) throw NoBridgeHere("no CONVERGE bridge is published for this platform");
            // Two platforms that name the same file are an ambiguous mapping, and a manifest that
            // contains one is not read further.
            std::map<std::string, std::string> claimed;
            for (const auto& kv : binaries->as_object()) {
                if (!kv.value().is_object()) continue;
                const auto path = str(kv.value().as_object(), "path");
                if (path.empty()) continue;
                if (auto it = claimed.find(path); it != claimed.end()) throw Failure("manifest maps " + it->second + " and " + std::string(kv.key()) + " to the same file");
                claimed[path] = std::string(kv.key());
            }
            auto* item = binaries->as_object().if_contains(here);
            if (!item || !item->is_object()) throw NoBridgeHere("the release has no bridge for " + here);
            // The entry picked for this machine must also say it is for this machine.
            const auto dash = here.find('-');
            const auto system = here.substr(0, dash), architecture = here.substr(dash + 1);
            for (const auto& [field, expected] : {std::pair{"os", system}, std::pair{"arch", architecture}}) {
                auto* stated = item->as_object().if_contains(field);
                if (stated && (!stated->is_string() || stated->get_string() != expected))
                    throw Failure("the bridge filed under " + here + " says " + field + " otherwise");
            }
            return described(here, item->as_object(), schema);
        }
    }
    auto* files = manifest.if_contains("files");
    if (!files || !files->is_object()) throw Failure("manifest has no files");
    auto* item = files->as_object().if_contains(key);
    if (!item || !item->is_object()) throw Failure("manifest is missing " + std::string(key));
    return described(key, item->as_object(), schema);
}

struct Manifest { json::object doc; int schema = 1; Semver version; std::string version_text; };

// The manifest as an object, or a refusal: a duplicate key, a schema newer than this file
// understands, or a top level that is not an object at all.
Manifest load_manifest(std::string_view raw) {
    if (has_duplicate_keys(raw)) throw Failure("manifest names something twice");
    auto v = parse_json(raw);
    if (!v || !v->is_object()) throw Failure("manifest is not an object");
    Manifest m;
    m.doc = v->as_object();
    if (auto* s = m.doc.if_contains("schema")) {
        if (!s->is_int64() || s->as_int64() < 1) throw Failure("manifest schema is not a version number");
        if (s->as_int64() > kManifestSchema) throw Failure("manifest schema is newer than this updater understands");
        m.schema = static_cast<int>(s->as_int64());
    }
    auto offered = semver(str(m.doc, "version"));
    if (!offered) throw Failure("manifest version is not MAJOR.MINOR.PATCH");
    m.version = *offered;
    m.version_text = semver_text(*offered);
    return m;
}

// The signed manifest of the release at `base`: fetched, verified against the compiled-in key
// before one value out of it is looked at, then parsed. A manifest that does not verify is not
// a manifest with a problem; it is not a CONVERGE manifest.
Manifest fetch_manifest(const std::string& base) {
    fetch::Options o;
    o.limit = kMaxManifest;
    o.user_agent = "converge-update/2";
    auto raw = fetch::get(base + "/manifest.json", o);
    if (!raw) throw Failure("could not fetch the release manifest: " + raw.error());
    auto sig = fetch::get(base + "/manifest.json.sig", o);
    if (!sig) throw Failure("release manifest is not signed");
    if (!signed_by_converge(*raw, *sig)) throw Failure("release manifest signature does not verify");
    return load_manifest(*raw);
}

std::string fetch_release_file(const std::string& base, const Described& d) {
    fetch::Options o;
    o.limit = kMaxFile;
    o.user_agent = "converge-update/2";
    auto data = fetch::get(base + "/" + d.path, o);
    if (!data) throw Failure("could not fetch " + d.path + ": " + data.error());
    if (d.size && static_cast<std::int64_t>(data->size()) != *d.size)
        throw Failure("size mismatch for " + d.path + " (" + std::to_string(data->size()) + " bytes, manifest says " + std::to_string(*d.size) + ")");
    if (hex_sha256(*data) != d.sha256) throw Failure("digest mismatch for " + d.path);
    return std::move(*data);
}

// ---- the updater --------------------------------------------------------------------------

// Replace one file, completely or not at all. rename either puts the new file there or leaves
// the old one untouched. On Unix a running bridge keeps the inode it is executing, so replacing
// it is safe. Windows cannot replace a file some process has open for execution, so there the
// old file is first renamed out of the way (which Windows does allow for a running image) and
// the new one put in its place; the leftover is removed on the next run.
void install_file(const fs::path& staged, const fs::path& target, bool executable) {
    std::error_code ec;
    fs::create_directories(target.parent_path(), ec);
    const auto name = platform::to_utf8(target.filename());
    const auto beside = target.parent_path() / ("." + name + ".converge-new");
    fs::copy_file(staged, beside, fs::copy_options::overwrite_existing);
    if (fs::exists(target, ec)) fs::permissions(beside, fs::status(target).permissions(), ec);
    else if (executable) fs::permissions(beside, fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read | fs::perms::others_exec, ec);
    else platform::make_private_file(beside);
    ec.clear();
    fs::rename(beside, target, ec);
    if (!ec) return;
    if (!platform::windows) { fs::remove(beside, ec); throw Failure("cannot replace " + platform::to_utf8(target)); }
    const auto retired = target.parent_path() / ("." + name + ".converge-old");
    fs::remove(retired, ec);
    ec.clear();
    fs::rename(target, retired, ec);
    if (ec) { fs::remove(beside, ec); throw Failure("cannot move " + platform::to_utf8(target) + " aside"); }
    fs::rename(beside, target, ec);
    if (ec) { fs::rename(retired, target, ec); fs::remove(beside, ec); throw Failure("cannot put the new " + name + " in place"); }
}

struct UpdateState {
    json::object doc;
    fs::path path;
    void save() { write_private(path, pretty(doc, true)); }
    void result(const std::string& text) { doc["last_result"] = text; save(); }
};

// One updater at a time, per installation, without ever making anything wait: an exclusive
// create of a file. A second invocation that finds it simply leaves rather than queueing. A lock
// left behind by a process that was killed is broken after `stale` seconds.
struct Lock {
    fs::path path;
    bool held = false;
    explicit Lock(fs::path p) : path(std::move(p)) {
        for (int attempt = 1; attempt <= 2; ++attempt) {
            if (platform::create_exclusive(path, std::to_string(platform::process_id()) + "\n")) { held = true; return; }
            if (attempt == 2) return;
            std::error_code ec;
            const auto written = fs::last_write_time(path, ec);
            if (ec) return;
            const auto age = std::chrono::duration_cast<std::chrono::seconds>(fs::file_time_type::clock::now() - written).count();
            if (age < 900) return;
            fs::remove(path, ec);   // abandoned by a process that did not finish
            if (ec) return;
        }
    }
    ~Lock() { if (held) { std::error_code ec; fs::remove(path, ec); } }
};

std::string check_update(const fs::path& directory, bool forced, bool verbose) {
    UpdateState state{read_json_object(directory / "update.json"), directory / "update.json"};
    const auto setup = read_json_object(directory / "setup.json");
    // No setup, nothing to update: a bridge run by hand, or a state directory setup never wrote
    // to. Decided before anything is recorded or fetched, so such a bridge never contacts the
    // release source at all.
    if (str(setup, "skill_dir").empty() && str(setup, "bridge").empty()) return "nothing to update";
    const auto now = now_seconds();
    if (!forced)
        if (auto* last = state.doc.if_contains("last_update_check"); last && last->is_int64() && now - last->as_int64() >= 0 && now - last->as_int64() < 3600)
            return "throttled";
    // The release source: the public source repository's releases, never the CONVERGE service.
    std::string base = str(setup, "release_base");
    if (base.empty()) base = default_release();
    while (base.ends_with('/')) base.pop_back();
    if (!fetch::parse_url(base)) return "no update source";
    // From here on the check has happened, whatever its outcome: record the attempt first, so a
    // source that hangs or fails every time is still only contacted once an hour.
    state.doc["last_update_check"] = now;
    if (!state.doc.contains("installed_version")) state.doc["installed_version"] = nullptr;
    state.save();

    Manifest manifest;
    try {
        manifest = fetch_manifest(base);
    } catch (const Failure& e) {
        state.result(std::string("check failed: ") + e.what());
        return "unreachable";
    }
    state.doc["latest_known_version"] = manifest.version_text;
    auto current = semver(str(state.doc, "installed_version"));
    if (!current) current = semver(str(setup, "skill_version"));
    if (!current) { state.result("installed version unknown; no update applied"); return "unknown current version"; }
    if (manifest.version <= *current) { state.result("up to date"); return "current"; }
    if (manifest.version.major != current->major) {
        // A new major version is a deliberate step, not something an hourly check takes on the
        // user's behalf. Say it is there, and leave the working installation exactly as it is.
        state.result("v" + manifest.version_text + " is available and is a new major version; it is not installed automatically");
        return "major version held";
    }

    // Where each updatable file lives on this machine, from the setup this installation already
    // has. Anything the setup does not name is simply not updated.
    // The skill is one file per AI client: setup installs it for each (`clients`), and an older
    // setup names its one client's directory as `skill_dir`.
    std::map<std::string, std::vector<fs::path>> where;
    std::error_code ec;
    std::vector<std::string> skill_dirs{str(setup, "skill_dir")};
    if (auto* clients = setup.if_contains("clients"); clients && clients->is_object())
        for (const auto& kv : clients->as_object())
            if (kv.value().is_object()) skill_dirs.push_back(str(kv.value().as_object(), "skill_dir"));
    for (const auto& skill_dir : skill_dirs)
        if (!skill_dir.empty() && fs::is_directory(platform::from_utf8(skill_dir), ec)) where["skill"].push_back(platform::from_utf8(skill_dir) / "SKILL.md");
    if (auto bridge = str(setup, "bridge"); !bridge.empty() && fs::is_directory(platform::from_utf8(bridge).parent_path(), ec)) where["bridge"].push_back(platform::from_utf8(bridge));
    if (where.empty()) { state.result("nothing to update"); return "nothing to update"; }

    const auto scratch = directory / ("converge-update-" + std::to_string(platform::process_id()));
    struct Cleanup { fs::path p; ~Cleanup() { std::error_code e; fs::remove_all(p, e); } } cleanup{scratch};
    platform::make_private_dir(scratch);
    std::map<std::string, fs::path> staged;
    try {
        for (const auto& [kind, targets] : where) {
            Described d;
            try {
                d = entry(manifest.doc, kind, manifest.schema);
            } catch (const NoBridgeHere&) {
                continue;   // no build published for this machine: the skill still updates, the bridge is left alone
            }
            auto data = fetch_release_file(base, d);
            const bool ok = kind == "skill" ? valid_skill(data) : platform::looks_like_executable(data);
            if (!ok) throw Failure("unexpected content for " + kind);
            const auto blob = scratch / kind;
            std::ofstream out(blob, std::ios::binary | std::ios::trunc);
            out.write(data.data(), static_cast<std::streamsize>(data.size()));
            if (!out) throw Failure("cannot stage " + kind);
            staged[kind] = blob;
        }
    } catch (const Failure& e) {
        state.result("v" + manifest.version_text + " not installed: " + e.what());
        return "rejected";
    }
    // Everything is present and verified before anything on disk is touched. An interruption
    // here leaves each file either the old one or the new one, never a fragment;
    // installed_version is written last, so a partial run is retried at the next check.
    try {
        for (const auto& [kind, blob] : staged)
            for (const auto& target : where[kind]) install_file(blob, target, kind == "bridge");
    } catch (const Failure& e) {
        state.result("v" + manifest.version_text + " partly installed: " + e.what() + " (retried at the next check)");
        return "failed";
    }
    state.doc["installed_version"] = manifest.version_text;
    state.result("v" + manifest.version_text + " installed; it runs from the next CONVERGE start");
    if (verbose) std::printf("CONVERGE v%s installed\n", manifest.version_text.c_str());
    return "installed";
}

// ---- setup -----------------------------------------------------------------------------------

// Everything that differs between AI hosts in installation and activation. The four CONVERGE is
// tested with: Claude Code, Codex, GitHub Copilot CLI and Cursor CLI.
struct Host {
    const char* id;                 // its key in setup.json's `clients`
    const char* name;               // what the person calls it
    const char* exe;                // the executable that says it is installed
    const char* skills;             // under the user's home
    std::vector<std::string> mcp_add;   // `<exe> mcp add <these> converge -- <command>`, where cli_add
    const char* mcp_file;           // under the user's home: where the client reads its MCP servers
    bool cli_add;                   // registered through `<exe> mcp add` while the client is installed
    const char* invoke;
    const char* hooks_file;         // under the user's home; "" = no hook that can show the user anything
    const char* hook_note;
    const char* hook_trust;
    const char* if_tools_missing;
};

const std::vector<Host>& hosts() {
    static const std::vector<Host> h{
        {"claude", "Claude Code", "claude", ".claude/skills", {"--scope", "user", "--transport", "stdio"}, ".claude.json", true, "/converge", ".claude/settings.json", "", "",
         "Claude Code starts MCP servers when a session starts. Open /mcp and reconnect \"converge\" if it is listed. If it is not "
         "listed, leave this session and run `claude --continue`: the conversation is kept."},
        {"codex", "Codex", "codex", ".agents/skills", {}, ".codex/config.toml", true, "$converge", ".codex/hooks.json",
         " Codex asks you to review this hook before it runs; see hook_trust.",
         // Codex records trust against the hook definition's hash, so a newly installed or updated
         // hook is skipped until the user reviews it. Say so plainly, say what it does, and leave
         // the decision entirely with them: nothing here ever writes Codex's trust state.
         "CONVERGE registers one Codex hook (PostToolUse on the converge_session tool) whose only job is to show each negotiation "
         "message to you the moment it arrives. Codex will ask you to review it before it runs: open /hooks, read what it does, and "
         "trust it only if you want to. Live per-exchange rendering starts once you do. Until then, and if you decline, CONVERGE works "
         "exactly as before: every message is still shown, together, when your AI ends its turn. Nothing is lost either way.",
         "Codex starts MCP servers when a session starts. Leave this session and run `codex resume`: the conversation is kept."},
        // Copilot CLI and Cursor CLI run hooks, but what a hook prints goes to the model, not to
        // the person, so there is no live hook here: each exchange is shown in the display that
        // ends the AI's turn, which the bridge carries in any case.
        {"copilot", "Copilot CLI", "copilot", ".copilot/skills", {}, ".copilot/mcp-config.json", true, "/converge", "", "", "",
         "Copilot CLI starts MCP servers when a session starts. Run /mcp reload, or leave this session and run `copilot --continue`: "
         "the conversation is kept."},
        {"cursor", "Cursor CLI", "cursor-agent", ".cursor/skills", {}, ".cursor/mcp.json", false, "/converge", "", "", "",
         "Cursor CLI starts MCP servers when a session starts. Leave this session and run `cursor-agent --continue`: the conversation is kept."},
    };
    return h;
}

const Host* host_named(const std::string& id) {
    for (const auto& h : hosts()) if (id == h.id) return &h;
    return nullptr;
}

constexpr std::string_view kAllowRule = "mcp__converge";
constexpr std::string_view kCursorRule = "Mcp(converge:*)";
constexpr std::string_view kCodexTable = "[mcp_servers.converge]";
constexpr std::string_view kCodexApprove = "default_tools_approval_mode = \"approve\"";

std::string_view trimmed(std::string_view s) {
    while (!s.empty() && (s.front() == ' ' || s.front() == '\t')) s.remove_prefix(1);
    while (!s.empty() && (s.back() == ' ' || s.back() == '\t' || s.back() == '\r')) s.remove_suffix(1);
    return s;
}

// Where a client reads its MCP servers, written by CONVERGE itself: for a client with no `mcp add`
// (Cursor CLI), and for one that is not installed yet, so that it finds CONVERGE the first time it
// runs. The entry is the one the client's own `mcp add` writes. Every other server, key, table and
// line is kept, and the original is backed up once.
//   Claude Code  ~/.claude.json              mcpServers.converge {type: stdio, command, args, env}
//   Codex        ~/.codex/config.toml        [mcp_servers.converge] command, args
//   Copilot CLI  ~/.copilot/mcp-config.json  mcpServers.converge {tools: ["*"], type: local, command, args}
//   Cursor CLI   ~/.cursor/mcp.json          mcpServers.converge {type: stdio, command, args}
bool toml_config(const Host& host) { return std::string_view(host.mcp_file).ends_with(".toml"); }

// The lines of CONVERGE's table in a TOML file: [first, end), or first == lines.size() when absent.
std::pair<std::size_t, std::size_t> toml_table(const std::vector<std::string>& lines) {
    std::size_t first = lines.size();
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const auto l = trimmed(lines[i]);
        if (first == lines.size()) { if (l == kCodexTable) first = i; continue; }
        if (l.starts_with('[')) return {first, i};
    }
    return {first, lines.size()};
}

std::vector<std::string> lines_of(const std::string& text) {
    std::vector<std::string> lines;
    for (std::size_t at = 0; at < text.size();) {
        const auto end = std::min(text.find('\n', at), text.size());
        lines.emplace_back(text.substr(at, end - at));
        at = end + 1;
    }
    return lines;
}

// Whether CONVERGE is registered in the client's file (a TOML table counts by its presence).
std::optional<json::object> file_server(const Host& host) {
    const auto text = read_file_if(platform::home() / platform::from_utf8(host.mcp_file));
    if (!text) return std::nullopt;
    if (toml_config(host)) {
        const auto lines = lines_of(*text);
        if (toml_table(lines).first == lines.size()) return std::nullopt;
        return json::object{};
    }
    auto v = parse_json(*text);
    if (!v || !v->is_object()) return std::nullopt;
    auto* servers = v->as_object().if_contains("mcpServers");
    if (!servers || !servers->is_object()) return std::nullopt;
    auto* mine = servers->as_object().if_contains("converge");
    if (!mine || !mine->is_object()) return std::nullopt;
    return mine->as_object();
}

bool register_in_file(const Host& host, const std::vector<std::string>& command) {
    const auto path = platform::home() / platform::from_utf8(host.mcp_file);
    try {
        const auto existing = read_file_if(path);
        std::string text;
        json::array args;
        for (std::size_t i = 1; i < command.size(); ++i) args.push_back(json::string(command[i]));
        if (toml_config(host)) {
            // A JSON string is a TOML basic string, and a JSON array of them a TOML array.
            const std::string cmd = "command = " + json::serialize(json::string(command.front()));
            const std::string arg = "args = " + json::serialize(args);
            auto lines = existing ? lines_of(*existing) : std::vector<std::string>{};
            auto [first, end] = toml_table(lines);
            if (first == lines.size()) {
                if (!lines.empty() && !trimmed(lines.back()).empty()) lines.emplace_back();
                lines.insert(lines.end(), {std::string(kCodexTable), cmd, arg});
            } else {
                // Only command and args: any other line of the table (an approval mode) stays.
                std::vector<std::string> table{lines[first], cmd, arg};
                for (std::size_t k = first + 1; k < end; ++k) {
                    const auto l = trimmed(lines[k]);
                    if (!l.starts_with("command") && !l.starts_with("args")) table.push_back(lines[k]);
                }
                lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(first), lines.begin() + static_cast<std::ptrdiff_t>(end));
                lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(first), table.begin(), table.end());
            }
            for (const auto& l : lines) text += l + "\n";
        } else {
            json::object config;
            if (existing) {
                auto v = parse_json(*existing);
                if (!v || !v->is_object()) return false;       // not ours to rewrite
                config = v->as_object();
            }
            auto* servers = config.if_contains("mcpServers");
            if (servers && !servers->is_object()) return false;
            if (!servers) servers = &(config["mcpServers"] = json::object{});
            const std::string id = host.id;
            json::object entry = id == "copilot" ? json::object{{"tools", json::array{"*"}}, {"type", "local"}}
                                                 : json::object{{"type", "stdio"}};
            entry["command"] = command.front();
            entry["args"] = args;
            if (id == "claude") entry["env"] = json::object{};
            servers->as_object()["converge"] = entry;
            text = pretty(config);
        }
        if (existing) {
            const auto backup = path.parent_path() / (platform::to_utf8(path.filename()) + ".before-converge");
            std::error_code ec;
            if (!fs::exists(backup, ec)) write_private(backup, *existing);
        }
        fs::create_directories(path.parent_path());
        write_private(path, text);
        return true;
    } catch (const std::exception&) {
        return false;
    }
}

// The clients setup connected, by id, from setup.json. A setup made before every client was
// connected names one `client`, with its skill directory, registration and hook at the top level.
json::object clients_of(const json::object& state) {
    json::object clients;
    if (auto* c = state.if_contains("clients"); c && c->is_object()) clients = c->as_object();
    if (const auto legacy = str(state, "client"); !legacy.empty() && !clients.contains(legacy)) {
        json::object one;
        for (const char* key : {"skill_dir", "registered_command", "live_hook"})
            if (auto* v = state.if_contains(key)) one[key] = *v;
        clients[legacy] = one;
    }
    return clients;
}

json::object public_status(const json::object& state, const fs::path& directory) {
    json::object out;
    for (const char* key : {"stage", "handle", "host_handle", "relay", "topic", "identity_public_key", "skill_version", "release_base"})
        if (auto* v = state.if_contains(key)) out[key] = *v;
    const auto clients = clients_of(state);
    json::object connected;
    std::string names;
    for (const auto& kv : clients) {
        const Host* host = host_named(kv.key());
        if (!kv.value().is_object()) continue;
        const auto& c = kv.value().as_object();
        // Installed or not is looked up now: a client installed since setup already has CONVERGE.
        const bool installed = host && !platform::which(host->exe).empty();
        connected[kv.key()] = !has(c, "registered_command") ? (str(c, "outcome").empty() ? std::string("not registered") : str(c, "outcome"))
                            : installed ? std::string("registered")
                                        : std::string("registered, ready for when it is installed");
        if (installed && has(c, "registered_command")) names += (names.empty() ? "" : ", ") + std::string(host->name);
    }
    out["clients"] = connected;
    // One line, for the installer to name them in what it asks.
    out["client_names"] = names;
    out["state_file"] = platform::to_utf8(directory / "setup.json");
    out["resume_prompt"] = "Continue my Converge setup.";
    const auto stage = str(state, "stage");
    if (stage == "registered") {
        out["next"] = "If converge_* tools are available in this session, CONVERGE is usable now: call converge_status.";
        json::object activation;
        for (const auto& kv : clients) {
            const Host* host = host_named(kv.key());
            if (!host || !kv.value().is_object()) continue;
            const auto& c = kv.value().as_object();
            if (!has(c, "registered_command")) continue;
            json::object a;
            a["usable_now_if"] = "converge_status is callable in this session";
            a["if_tools_missing"] = std::string(host->if_tools_missing) + " Then say: Continue my Converge setup.";
            a["invoke"] = host->invoke;
            const bool live = str(c, "live_hook") == "installed";
            a["live_view"] = live ? "Each exchange is shown live through a host hook." + std::string(host->hook_note)
                                  : "No live hook: exchanges are shown when the AI ends its turn.";
            if (live && *host->hook_trust) a["hook_trust"] = host->hook_trust;
            activation[kv.key()] = a;
        }
        // By client: the AI reading this takes the entry for the client it runs in.
        out["activation"] = activation;
        out["delivery"] = "Nothing to pay and no wallet needed. Without CONVERGE balance, messages may be throttled with a "
                          "small delay, and CONVERGE says so when it happens, with a link that makes them faster. "
                          "Following that link is optional.";
    }
    return out;
}

bool ours(const json::value& entry) {
    if (!entry.is_object()) return false;
    const auto& o = entry.as_object();
    return str(o, "matcher") == kHookMatcher;
}

// Registers the live renderer (this executable's `live` subcommand) as a PostToolUse hook of
// this host. It is how each exchange of an automatic negotiation reaches the user while it
// happens; without it the bridge still shows everything, in the display that ends the AI's
// turn. Never fatal: other hooks are preserved, and the original file is backed up once.
std::string install_live_hook(const Host& host, const fs::path& bridge) {
    const auto path = platform::home() / platform::from_utf8(host.hooks_file);
    const auto command = platform::quote_for_host({platform::to_utf8(bridge), "live"});
    try {
        json::object config;
        const auto existing = read_file_if(path);
        if (existing) {
            auto v = parse_json(*existing);
            if (!v || !v->is_object()) return "unreadable";
            config = v->as_object();
        }
        auto* hooks = config.if_contains("hooks");
        if (hooks && !hooks->is_object()) return "unreadable";
        if (!hooks) hooks = &(config["hooks"] = json::object{});
        auto* entries = hooks->as_object().if_contains("PostToolUse");
        if (entries && !entries->is_array()) return "unreadable";
        if (!entries) entries = &(hooks->as_object()["PostToolUse"] = json::array{});
        json::object mine{{"matcher", kHookMatcher},
                          {"hooks", json::array{json::object{{"type", "command"}, {"command", command}, {"timeout", 10}}}}};
        json::array kept;
        for (const auto& e : entries->as_array()) if (!ours(e)) kept.push_back(e);
        kept.push_back(mine);
        if (kept == entries->as_array()) return "installed";
        if (existing) {
            const auto backup = path.parent_path() / (platform::to_utf8(path.filename()) + ".before-converge");
            std::error_code ec;
            if (!fs::exists(backup, ec)) write_private(backup, *existing);
        }
        hooks->as_object()["PostToolUse"] = kept;
        write_private(path, pretty(config));
        return "installed";
    } catch (const std::exception&) {
        return "unreadable";
    }
}

// The person's own trust decision: whether their AI client runs CONVERGE's tools without asking
// each time. Written only when the person asks for it (setup --allow-tools; the installer asks
// them at their own terminal, and sets it only on a yes), never as a side effect of setup, and in
// the client's own terms: Claude Code, one allow rule "mcp__converge" in ~/.claude/settings.json;
// Codex, default_tools_approval_mode = "approve" in the [mcp_servers.converge] table of
// ~/.codex/config.toml. Everything else in the file is kept, the original is backed up once, and
// a file that cannot be read is left alone.
std::string change_codex_trust(bool allow) {
    const auto path = platform::home() / ".codex" / "config.toml";
    const auto existing = read_file_if(path);
    if (!existing) return allow ? "left alone: ~/.codex/config.toml does not exist; run setup first" : "nothing to remove";
    std::vector<std::string> lines;
    for (std::size_t at = 0; at < existing->size();) {
        const auto end = std::min(existing->find('\n', at), existing->size());
        lines.emplace_back(existing->substr(at, end - at));
        at = end + 1;
    }
    // CONVERGE's table, as `codex mcp add` writes it, and within it the approval line if any.
    std::size_t table = lines.size(), mine = lines.size();
    for (std::size_t i = 0; i < lines.size(); ++i) {
        const auto l = trimmed(lines[i]);
        if (table == lines.size()) { if (l == kCodexTable) table = i; continue; }
        if (l.starts_with('[')) break;
        if (l.starts_with("default_tools_approval_mode")) { mine = i; break; }
    }
    if (table == lines.size()) return allow ? "left alone: converge is not registered in ~/.codex/config.toml" : "nothing to remove";
    if (allow) {
        if (mine != lines.size() && trimmed(lines[mine]) == kCodexApprove) return "allowed already";
        if (mine != lines.size()) lines[mine] = std::string(kCodexApprove);
        else lines.insert(lines.begin() + static_cast<std::ptrdiff_t>(table) + 1, std::string(kCodexApprove));
    } else {
        // Only the line this setting writes: an approval mode the person chose by hand stays theirs.
        if (mine == lines.size() || trimmed(lines[mine]) != kCodexApprove) return "nothing to remove";
        lines.erase(lines.begin() + static_cast<std::ptrdiff_t>(mine));
    }
    std::string text;
    for (std::size_t i = 0; i < lines.size(); ++i) text += lines[i] + (i + 1 < lines.size() ? "\n" : "");
    if (existing->ends_with('\n')) text += '\n';
    const auto backup = path.parent_path() / "config.toml.before-converge";
    std::error_code ec;
    if (!fs::exists(backup, ec)) write_private(backup, *existing);
    write_private(path, text);
    return allow ? "allowed" : "removed";
}

std::string change_tools_rule(bool allow, const fs::path& path, std::string_view wanted) {
    try {
        json::object config;
        const auto existing = read_file_if(path);
        if (existing) {
            auto v = parse_json(*existing);
            if (!v || !v->is_object()) return "left alone: " + platform::to_utf8(path) + " could not be read";
            config = v->as_object();
        } else if (!allow) {
            return "nothing to remove";
        }
        auto* permissions = config.if_contains("permissions");
        if (permissions && !permissions->is_object()) return "left alone: its permissions are not an object";
        if (!permissions) permissions = &(config["permissions"] = json::object{});
        auto* list = permissions->as_object().if_contains("allow");
        if (list && !list->is_array()) return "left alone: its allow list is not a list";
        if (!list) list = &(permissions->as_object()["allow"] = json::array{});
        json::array kept;
        bool present = false;
        for (const auto& rule : list->as_array()) {
            const bool mine = rule.is_string() && rule.get_string() == wanted;
            present = present || mine;
            if (!mine) kept.push_back(rule);
        }
        if (allow == present) return allow ? "allowed already" : "nothing to remove";
        if (allow) kept.push_back(json::string(wanted));
        if (existing) {
            const auto backup = path.parent_path() / (platform::to_utf8(path.filename()) + ".before-converge");
            std::error_code ec;
            if (!fs::exists(backup, ec)) write_private(backup, *existing);
        }
        permissions->as_object()["allow"] = kept;
        fs::create_directories(path.parent_path());
        write_private(path, pretty(config));
        return allow ? "allowed" : "removed";
    } catch (const std::exception&) {
        return "left alone: " + platform::to_utf8(path) + " could not be changed";
    }
}

// Takes CONVERGE's live-render hook out of this host's configuration and leaves everything else
// exactly as it was: not other hooks, not other events, not the host's other settings, and not
// any trust state, which belongs to the user and to the host. Running it twice is not an error,
// and a configuration file it cannot parse is left untouched rather than rewritten.
std::string remove_live_hook(const Host& host) {
    if (!*host.hooks_file) return "nothing to remove";
    const auto path = platform::home() / platform::from_utf8(host.hooks_file);
    const auto existing = read_file_if(path);
    if (!existing) return "nothing to remove";
    auto v = parse_json(*existing);
    if (!v) return "left alone: this host configuration could not be read";
    if (!v->is_object()) return "nothing to remove";
    auto& config = v->as_object();
    auto* hooks = config.if_contains("hooks");
    if (!hooks || !hooks->is_object()) return "nothing to remove";
    auto* entries = hooks->as_object().if_contains("PostToolUse");
    if (!entries || !entries->is_array()) return "nothing to remove";
    json::array kept;
    for (const auto& e : entries->as_array()) if (!ours(e)) kept.push_back(e);
    const auto removed = entries->as_array().size() - kept.size();
    if (removed == 0) return "nothing to remove";
    const auto backup = path.parent_path() / (platform::to_utf8(path.filename()) + ".before-converge");
    std::error_code ec;
    if (!fs::exists(backup, ec)) write_private(backup, *existing);
    if (!kept.empty()) hooks->as_object()["PostToolUse"] = kept;
    else {
        hooks->as_object().erase("PostToolUse");
        if (hooks->as_object().empty()) config.erase("hooks");
    }
    write_private(path, pretty(config));
    return "removed " + std::to_string(removed) + " CONVERGE hook entr" + (removed == 1 ? "y" : "ies");
}

// What the updater compares against. Setup is the only thing that knows the version of an
// installation it just made; after that the updater owns this file.
void seed_update_state(const fs::path& directory, const std::string& skill_version) {
    auto state = read_json_object(directory / "update.json");
    if (!skill_version.empty()) {
        state["installed_version"] = skill_version;
        if (!state.contains("latest_known_version")) state["latest_known_version"] = skill_version;
    }
    if (!state.contains("last_update_check")) state["last_update_check"] = 0;
    if (!state.contains("last_result")) state["last_result"] = "installed by setup";
    write_private(directory / "update.json", pretty(state, true));
}

// An HTTPS origin (HTTP only for a local development relay), with nothing after the host.
std::string origin(const std::string& value) {
    auto u = fetch::parse_url(value);
    if (!u || (u->path != "/" && !u->path.empty())) throw Failure("--base must be an HTTPS origin");
    if (!u->tls && u->host != "127.0.0.1" && u->host != "localhost" && u->host != "::1" && u->host != "[::1]")
        throw Failure("HTTP is permitted only for a local development relay");
    const bool default_port = u->port == (u->tls ? "443" : "80");
    return std::string(u->tls ? "https://" : "http://") + u->host + (default_port ? "" : ":" + u->port);
}

bool plain_handle(std::string_view h) {
    return h.size() == 16 && h.starts_with("cvh_") && std::all_of(h.begin() + 4, h.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}
bool plain_invite(std::string_view c) {
    return c.size() > 4 && c.starts_with("cvi_") && std::all_of(c.begin() + 4, c.end(), [](char c) { return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f'); });
}

json::array command_array(const std::vector<std::string>& parts) {
    json::array a;
    for (const auto& p : parts) a.emplace_back(p);
    return a;
}

std::string public_key_line(const std::string& identity_file) {
    std::string err;
    auto signer = make_file_signer(identity_file, true, &err);
    if (!signer) throw Failure(err);
    return signer->public_ssh_line();
}

// Redeems a host-paid invitation on the link: one connection with the redeem intent, whose
// welcome names the member this key became and the host it may call. The relay binds the key,
// creates the member and consumes the code in one transaction; nothing is sent but a signature.
struct Redeemed { std::string handle, host_handle; };
Redeemed redeem_invite(const std::string& relay_url, const std::string& identity_file, const fs::path& pin_store,
                       const std::string& code, const std::string& alias, int intent = 1) {
    std::string err;
    auto signer = make_file_signer(identity_file, true, &err);
    if (!signer) throw Failure(err);
    auto parsed = parse_ssh_ed25519(signer->public_ssh_line());
    if (!parsed) throw Failure("the identity is not an ed25519 key");
    Credentials creds;
    creds.identity = parsed->raw;
    creds.alias = alias;
    creds.intent = intent;   // 1 redeem a host-paid invitation, 2 link a cost-sharing one
    creds.invite_code = code;
    creds.sign = [s = signer.get()](std::string_view m) { return s->sign(m); };
    crypto::Identity ephemeral;
    RelayClient relay(relay_url, creds, ephemeral.pub_b64());
    const auto url = RelayClient::parse_url(relay_url);
    const std::string pin_name = "relay:" + (url ? url->host : relay_url);
    relay.set_relay_key_store(
        [&]() -> std::optional<RelayClient::RelayKey> {
            std::ifstream in(pin_store);
            for (std::string line; std::getline(in, line);)
                if (line.starts_with(pin_name + " ")) return link::identity_from_text(line.substr(pin_name.size() + 1));
            return std::nullopt;
        },
        [&](const RelayClient::RelayKey& k) {
            platform::make_private_dir(pin_store.parent_path());
            std::string kept;
            { std::ifstream in(pin_store); for (std::string line; std::getline(in, line);) if (!line.starts_with(pin_name + " ")) kept += line + "\n"; }
            write_private(pin_store, kept + pin_name + " " + link::identity_text(k) + "\n");
        });
    relay.start();
    const auto deadline = std::chrono::steady_clock::now() + std::chrono::seconds(20);
    std::string refusal;
    while (std::chrono::steady_clock::now() < deadline) {
        auto ev = relay.wait_event(500);
        if (!ev) continue;
        if (ev->kind != RelayEvent::Kind::text) continue;
        auto v = parse_json(ev->json);
        if (!v || !v->is_object()) continue;
        const auto& o = v->as_object();
        if (ev->t == "welcome") {
            Redeemed r{str(o, "handle"), str(o, "host_handle")};
            relay.stop();
            if (r.handle.empty()) throw Failure("Invite redemption did not register the local identity; request a fresh invite if it was consumed.");
            return r;
        }
        if (ev->t == "error") { refusal = str(o, "msg"); if (refusal.empty()) refusal = str(o, "code"); relay.stop(); break; }
    }
    relay.stop();
    if (refusal.empty()) throw Failure("Could not reach Converge; check the connection and retry setup.");
    throw Failure(refusal);
}

// The host a guest was invited by, saved in the guest's own connections (connections.json, which
// the bridge reads) under the name the invitation gave, unless the guest named them already. Local
// only: the relay never carries it, and the guest may rename the host whenever they like.
void name_host(const fs::path& directory, const std::string& host_handle, const std::string& given) {
    const auto name = ux::one_line(given, 60);
    if (host_handle.empty() || name.empty()) return;
    const auto path = directory / "connections.json";
    auto doc = read_json_object(path);
    auto* list = doc.if_contains("connections");
    if (!list || !list->is_array()) { doc["connections"] = json::array{}; list = &doc["connections"]; }
    for (auto& item : list->as_array())
        if (item.is_object() && str(item.as_object(), "handle") == host_handle) {
            if (str(item.as_object(), "label").empty()) { item.as_object()["label"] = name; write_private(path, json::serialize(doc) + "\n"); }
            return;
        }
    list->as_array().push_back(json::object{{"handle", host_handle}, {"label", name}, {"first_seen", now_seconds()}});
    write_private(path, json::serialize(doc) + "\n");
}

struct SetupArgs {
    std::string base, release_base, state_dir, bridge, handle, invite, link, alias, topic, peer_name;
    bool no_live_hook = false, remove_live_hook = false, status = false, allow_tools = false, disallow_tools = false;
};

int run_setup(const SetupArgs& args) {
    const fs::path directory = args.state_dir.empty() ? platform::state_dir() : resolve_dir(args.state_dir);
    auto state = read_json_object(directory / "setup.json");
    auto save = [&] { write_private(directory / "setup.json", pretty(state)); };
    auto print_status = [&] { std::printf("%s", pretty(public_status(state, directory)).c_str()); std::fflush(stdout); };
    if (args.status) { print_status(); return 0; }
    if (args.allow_tools || args.disallow_tools) {
        // Every client this setup connected, each in its own terms.
        json::object out;
        const std::string back = std::string("`converge-bridge setup --") + (args.allow_tools ? "disallow" : "allow") + "-tools` changes it back";
        for (const auto& kv : clients_of(state)) {
            const std::string client = kv.key();
            json::object one;
            if (client == "claude") {
                one["tools_rule"] = change_tools_rule(args.allow_tools, platform::home() / ".claude" / "settings.json", kAllowRule);
                one["note"] = "The one rule \"" + std::string(kAllowRule) + "\" in ~/.claude/settings.json, and nothing else, was considered. "
                              "It is the person's own choice; " + back + ", and so does /permissions in Claude Code.";
            } else if (client == "codex") {
                one["tools_rule"] = change_codex_trust(args.allow_tools);
                one["note"] = "The one line " + std::string(kCodexApprove) + " in the " + std::string(kCodexTable) + " table of ~/.codex/config.toml, "
                              "and nothing else, was considered. It is the person's own choice; " + back + ".";
            } else if (client == "cursor") {
                one["tools_rule"] = change_tools_rule(args.allow_tools, platform::home() / ".cursor" / "cli-config.json", kCursorRule);
                one["note"] = "The one rule \"" + std::string(kCursorRule) + "\" in ~/.cursor/cli-config.json, and nothing else, was considered. "
                              "It is the person's own choice; " + back + ".";
            } else if (client == "copilot") {
                one["tools_rule"] = "not applicable";
                one["note"] = "Copilot CLI keeps tool approvals per folder, not per person: approve Converge's tools when it asks, or start "
                              "it with --allow-tool='converge'.";
            } else {
                one["tools_rule"] = "not applicable";
                one["note"] = "This client keeps its own approvals; set them there.";
            }
            out[client] = one;
        }
        std::printf("%s", pretty(json::object{{"clients", out}}).c_str());
        return 0;
    }
    if (args.remove_live_hook) {
        // From every client that can have one, whatever this setup recorded: taking out only
        // CONVERGE's own entry is harmless where there is none.
        json::object outcomes;
        auto clients = clients_of(state);
        bool changed = false;
        for (const auto& h : hosts()) {
            if (!*h.hooks_file) continue;
            const auto outcome = remove_live_hook(h);
            outcomes[h.id] = outcome;
            if (auto* c = clients.if_contains(h.id); c && c->is_object() && str(c->as_object(), "live_hook") == "installed" && outcome.starts_with("removed")) {
                c->as_object()["live_hook"] = "removed";
                changed = true;
            }
        }
        if (changed) { state["clients"] = clients; for (const char* k : {"client", "skill_dir", "registered_command", "live_hook"}) state.erase(k); save(); }
        json::object out{{"live_hook", outcomes},
                         {"note", "Only CONVERGE's own PostToolUse entry was touched. Nothing else in these hosts' configuration, and no "
                                  "trust state, was changed. CONVERGE still shows every exchange; without the hook they appear together "
                                  "when the AI ends its turn."}};
        std::printf("%s", pretty(out).c_str());
        return 0;
    }

    const auto base = origin(!args.base.empty() ? args.base : has(state, "base") ? str(state, "base") : default_base());
    std::string release = !args.release_base.empty() ? args.release_base : has(state, "release_base") ? str(state, "release_base") : default_release();
    while (release.ends_with('/')) release.pop_back();
    if (!fetch::parse_url(release)) throw Failure("--release-base must be an http(s) URL");
    // Every supported AI client is connected, all serving this one setup: one identity and one
    // account, whichever client the person opens. One that is installed is registered through its
    // own `mcp add`; one that is not yet is written into the file it will read, so it finds
    // CONVERGE the first time it runs.
    auto clients = clients_of(state);
    struct Found { const Host* host; std::string cli; bool registered; };
    std::vector<Found> found;
    for (const auto& h : hosts()) {
        const auto path = platform::which(h.exe);
        std::string cli = path.empty() ? std::string() : platform::to_utf8(path);
        if (!cli.empty() && platform::run_and_wait({cli, "--version"}) != 0) cli.clear();   // one that does not run is set up as not installed
        json::object mine = clients.contains(h.id) && clients.at(h.id).is_object() ? clients.at(h.id).as_object() : json::object{};
        mine["installed"] = !cli.empty();
        // A registration this setup did not make is someone's own configuration: left as it is.
        const bool registered = h.cli_add && !cli.empty() ? platform::run_and_wait({cli, "mcp", "get", "converge"}) == 0
                                                          : file_server(h).has_value();
        if (registered && !has(mine, "registered_command"))
            mine["outcome"] = "left alone: Converge is already registered in " + std::string(h.name) + " outside this helper";
        else found.push_back({&h, cli, registered});
        clients[h.id] = mine;
    }
    if (found.empty()) {
        for (const auto& kv : clients)
            if (auto why = str(kv.value().as_object(), "outcome"); why.starts_with("left alone"))
                throw Failure(why + ". Use converge_status and the setup guide; existing configuration was preserved.");
    }
    if (!state.empty() && str(state, "base") != base)
        throw Failure("This setup belongs to another relay; use a separate --state-dir.");
    if (!args.handle.empty() && !plain_handle(args.handle)) throw Failure("--handle must be the public cvh_ handle that Link an AI session shows at the Converge site");
    if (!args.invite.empty() && !plain_invite(args.invite)) throw Failure("--invite must be a cvi_ invitation code");
    if (!args.link.empty() && !plain_invite(args.link)) throw Failure("--link must be a cvi_ invitation code");
    if ((!args.handle.empty()) + (!args.invite.empty()) + (!args.link.empty()) > 1) throw Failure("Use one of --handle, --invite or --link");
    if (!args.handle.empty() && has(state, "handle") && args.handle != str(state, "handle"))
        throw Failure("This setup already has a different member; use a separate --state-dir.");
    if (!args.invite.empty() && has(state, "handle") && str(state, "invite_hash") != hex_sha256(args.invite))
        throw Failure("This session already has a member. Keep it and follow the existing-account pairing guide.");

    platform::make_private_dir(directory);
    fetch::Options o;
    o.limit = kMaxManifest;
    o.user_agent = "converge-setup/2";
    auto skill = fetch::get(release + "/skill.md", o);
    if (!skill) throw Failure("Could not fetch the Converge skill from " + release + ": " + skill.error());
    if (!valid_skill(*skill)) throw Failure("The downloaded Converge skill is not a valid SKILL.md; nothing installed.");
    const auto skill_version = skill_version_of(*skill);
    for (const auto& f : found) {
        auto& mine = clients[f.host->id].as_object();
        const fs::path skill_dir = has(mine, "skill_dir") ? platform::from_utf8(str(mine, "skill_dir"))
                                                          : platform::home() / platform::from_utf8(f.host->skills) / "converge";
        const auto target = skill_dir / "SKILL.md";
        if (auto current = read_file_if(target); current && *current != *skill) {
            const auto backup = skill_dir / "SKILL.md.before-converge-setup";
            std::error_code ec;
            if (!fs::exists(backup, ec)) write_private(backup, *current);
        }
        write_private(target, *skill);
        write_private(skill_dir / "setup-location.txt", platform::to_utf8(directory) + "\n");
        mine["skill_dir"] = platform::to_utf8(skill_dir);
    }

    // The bridge: this executable, or one the user named. A managed bridge lives at the platform's
    // place for it and is this very program, copied there when setup runs from somewhere else (a
    // fresh download, say); the updater keeps it current from then on.
    const auto self = platform::executable_path();
    const auto default_bridge = platform::managed_bridge_path();
    fs::path bridge = !args.bridge.empty() ? resolve_dir(args.bridge)
                    : has(state, "bridge") ? platform::from_utf8(str(state, "bridge")) : default_bridge;
    const bool managed = args.bridge.empty() && bridge == default_bridge;
    if (managed) {
        std::error_code ec;
        if (!self.empty() && !fs::equivalent(self, bridge, ec)) {
            const auto mine = read_file(self);
            if (read_file_if(bridge) != mine) {
                fs::create_directories(bridge.parent_path(), ec);
                const auto staged = directory / "bridge.staged";
                write_private(staged, mine);
                install_file(staged, bridge, true);
                fs::remove(staged, ec);
            }
        }
    } else {
        std::error_code ec;
        if (!fs::is_regular_file(bridge, ec)) throw Failure("--bridge does not exist");
    }
    if (platform::run_and_wait({platform::to_utf8(bridge), "--help"}) != 0) throw Failure("the bridge at " + platform::to_utf8(bridge) + " does not run");

    for (const auto& f : found) {
        auto& mine = clients[f.host->id].as_object();
        if (!*f.host->hooks_file) mine["live_hook"] = "not available on this client";
        else if (!args.no_live_hook) mine["live_hook"] = install_live_hook(*f.host, bridge);
    }
    auto relay_url = std::string(base.starts_with("https:") ? "wss://" : "ws://") + base.substr(base.find("//") + 2) + "/link";
    state["version"] = 1;
    state["base"] = base;
    state["release_base"] = release;
    for (const char* key : {"client", "skill_dir", "registered_command", "live_hook"}) state.erase(key);   // now under `clients`
    state["clients"] = clients;
    state["bridge"] = platform::to_utf8(bridge);
    state["relay"] = relay_url;
    if (!has(state, "identity_file")) state["identity_file"] = platform::to_utf8(directory / "identity");
    state["skill_version"] = skill_version;
    if (!has(state, "stage")) state["stage"] = "installed_skill";
    seed_update_state(directory, skill_version);
    if (!args.topic.empty()) state["topic"] = args.topic;
    save();
    // Keep a managed install current: the updater, forced, so a resumed setup runs the release's
    // bridge. Its outcome is never setup's failure.
    if (managed) { try { (void)check_update(directory, true, false); } catch (...) {} }

    const auto identity_file = str(state, "identity_file");
    if (!args.invite.empty() && !has(state, "handle")) {
        const auto pub = public_key_line(identity_file);
        const auto guest = redeem_invite(relay_url, identity_file, directory / "known_peers", args.invite, args.alias.empty() ? "guest" : args.alias);
        // Persist the handle immediately: if client registration fails, rerunning setup won't
        // attempt to redeem the now-consumed code again.
        state["handle"] = guest.handle;
        state["host_handle"] = guest.host_handle;
        state["identity_public_key"] = pub;
        state["invite_hash"] = hex_sha256(args.invite);
        state["stage"] = "credential_saved";
        save();
    } else if (!args.link.empty()) {
        // A cost-sharing invitation, linked by this key: the member it already is (registered at
        // the site), or its own account, made now. The relay decides; the welcome says which.
        const auto pub = public_key_line(identity_file);
        const auto linked = redeem_invite(relay_url, identity_file, directory / "known_peers", args.link, args.alias.empty() ? "self" : args.alias, 2);
        if (has(state, "handle") && str(state, "handle") != linked.handle)
            throw Failure("The relay linked the invitation to " + linked.handle + ", not this setup's member " + str(state, "handle") + "; use a separate --state-dir.");
        state["handle"] = linked.handle;
        state["host_handle"] = linked.host_handle;
        state["identity_public_key"] = pub;
        if (str(state, "stage") != "registered") state["stage"] = "credential_saved";
        save();
    } else if (!has(state, "key")) {
        const auto line = public_key_line(identity_file);
        state["identity_public_key"] = line;
        if (!args.handle.empty()) state["handle"] = args.handle;
        if (!has(state, "handle")) {
            // No wallet, no website, no handle to fetch: the key is its own account on the relay,
            // and its handle is derived from the key exactly as the relay derives it. A wallet
            // can claim the key later (Link an AI session), for a balance and faster delivery.
            auto parsed = parse_ssh_ed25519(line);
            if (!parsed) throw Failure("the identity is not an ed25519 key");
            state["handle"] = link::handle_of(parsed->raw);
        }
        if (str(state, "stage") != "registered") state["stage"] = "credential_saved";
        save();
    }

    if (!args.peer_name.empty()) name_host(directory, str(state, "host_handle"), args.peer_name);

    const std::vector<std::string> command{platform::to_utf8(bridge), "serve", "--state-dir", platform::to_utf8(directory)};
    const auto wanted = command_array(command);
    // Each client on its own: one that cannot be registered now is retried by the next setup and
    // does not hold back the others. Setup fails only for an installed client, the one the person
    // is about to use.
    std::string failed;
    for (const auto& f : found) {
        auto& mine = clients[f.host->id].as_object();
        auto* registered = mine.if_contains("registered_command");
        if (!registered || *registered != wanted || !f.registered) {
            bool ok;
            if (!f.host->cli_add || f.cli.empty()) {
                ok = register_in_file(*f.host, command);
            } else {
                std::vector<std::string> registration{f.cli, "mcp", "add"};
                registration.insert(registration.end(), f.host->mcp_add.begin(), f.host->mcp_add.end());
                registration.push_back("converge");
                registration.push_back("--");
                registration.insert(registration.end(), command.begin(), command.end());
                ok = platform::run_and_wait(registration) == 0;
            }
            if (!ok) {
                mine.erase("registered_command");
                mine["outcome"] = std::string(f.host->name) + ": registration failed; run setup again to retry";
                if (!f.cli.empty()) failed += (failed.empty() ? "" : "; ") + str(mine, "outcome");
                continue;
            }
            mine["registered_command"] = wanted;
        }
        mine.erase("outcome");
    }
    state["clients"] = clients;
    if (!failed.empty()) { save(); throw Failure(failed + "; the saved setup is kept"); }
    state["stage"] = "registered";
    save();
    print_status();
    return 0;
}

// ---- the live renderer --------------------------------------------------------------------

// The bridge's result is JSON text somewhere inside the host's tool_response.
std::optional<json::object> find_live(const json::value& v) {
    if (v.is_string()) {
        const auto s = v.get_string();
        if (s.find("\"live\"") == std::string::npos) return std::nullopt;
        auto doc = parse_json(s);
        if (!doc || !doc->is_object()) return std::nullopt;
        auto* live = doc->as_object().if_contains("live");
        if (live && live->is_object()) return live->as_object();
        return std::nullopt;
    }
    if (v.is_object()) { for (const auto& kv : v.as_object()) if (auto f = find_live(kv.value())) return f; }
    if (v.is_array()) { for (const auto& item : v.as_array()) if (auto f = find_live(item)) return f; }
    return std::nullopt;
}

// Only ever a "<process id>.ack" inside a "live" directory that belongs to this user. The bridge
// builds this path out of its own state directory and its own process id; nothing a remote party
// sends ever reaches it. The checks are here anyway, because a renderer that writes where it is
// told is a renderer that can be told anywhere.
void record_ack(const std::string& ack, std::int64_t id) {
    const auto path = platform::from_utf8(ack);
    const auto name = platform::to_utf8(path.filename());
    if (name.size() < 5 || !name.ends_with(".ack")) return;
    const auto digits = name.substr(0, name.size() - 4);
    if (digits.empty() || digits.find_first_not_of("0123456789") != std::string::npos) return;
    if (platform::to_utf8(path.parent_path().filename()) != "live") return;
    if (!platform::owned_private_dir(path.parent_path())) return;
    std::error_code ec;
    if (fs::exists(fs::symlink_status(path, ec))) {
        if (platform::is_reparse_point(path) || !fs::is_regular_file(fs::symlink_status(path, ec))) return;
    }
    platform::append_no_follow(path, std::to_string(id) + "\n");
}

} // namespace

// ---- entry points ---------------------------------------------------------------------------

int live() {
    try {
        std::string input((std::istreambuf_iterator<char>(std::cin)), {});
        auto event = parse_json(input);
        if (!event || !event->is_object()) return 0;
        const auto& o = event->as_object();
        if (!str(o, "tool_name").ends_with("converge_session")) return 0;
        auto* response = o.if_contains("tool_response");
        if (!response) return 0;
        auto live = find_live(*response);
        if (!live) return 0;
        auto* text = live->if_contains("text");
        auto* id = live->if_contains("id");
        if (!text || !text->is_string() || !id || !id->is_int64()) return 0;
        // The host prints this after a prefix of its own ("PostToolUse:... says:"). A piece of
        // several lines starts on the next line, so a banner or a framed message keeps its first
        // row in line with the rest; a one line piece reads naturally after the prefix.
        const std::string shown = std::string(text->get_string());
        const std::string message = shown.find('\n') != std::string::npos ? "\n" + shown : shown;
        const std::string out = json::serialize(json::object{{"systemMessage", message}}) + "\n";
        std::fwrite(out.data(), 1, out.size(), stdout);
        std::fflush(stdout);
        if (auto* ack = live->if_contains("ack"); ack && ack->is_string()) record_ack(std::string(ack->get_string()), id->as_int64());
    } catch (...) {
        // a renderer must never break the tool call it watches
    }
    return 0;
}

int update(const std::vector<std::string>& args) {
    bool forced = false, verbose = false;
    std::string state_dir;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        if (a == "--check") continue;
        else if (a == "--force") forced = true;
        else if (a == "--verbose") verbose = true;
        else if (a == "--state-dir") { if (i + 1 >= args.size()) return 2; state_dir = args[++i]; }
        else { std::fprintf(stderr, "usage: converge-bridge update [--check] [--force] [--verbose] [--state-dir DIR]\n"); return 2; }
    }
    const fs::path directory = state_dir.empty() ? platform::state_dir() : resolve_dir(state_dir);
    std::error_code ec;
    if (!fs::is_directory(directory, ec)) return 0;
    Lock lock(directory / "update.lock");
    if (!lock.held) {
        // Another invocation is checking or installing. This one does not queue behind it and
        // does not check again: it simply goes on with the installation that is already there.
        if (verbose) std::printf("another CONVERGE update is in progress\n");
        return 0;
    }
    try {
        const auto outcome = check_update(directory, forced, verbose);
        if (verbose) std::printf("%s\n", outcome.c_str());
    } catch (const std::exception& e) {       // nothing here may ever escape into the host
        if (verbose) std::fprintf(stderr, "converge update: %s\n", e.what());
    }
    return 0;
}

// What the installer asks before it puts a download in place: is this file the bridge the
// release's signed manifest names for this machine? The manifest is fetched and its signature
// verified against the compiled-in release key; the file's size and SHA-256 must match.
int verify_release(const std::vector<std::string>& args) {
    std::string release, file;
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& a = args[i];
        if (a == "--release") { if (i + 1 >= args.size()) return 2; release = args[++i]; }
        else if (a == "--file") { if (i + 1 >= args.size()) return 2; file = args[++i]; }
        else { std::fprintf(stderr, "usage: converge-bridge verify-release --release URL --file PATH\n"); return 2; }
    }
    if (release.empty()) release = default_release();
    while (release.ends_with('/')) release.pop_back();
    try {
        const auto manifest = fetch_manifest(release);
        const auto d = entry(manifest.doc, "bridge", manifest.schema);
        const auto data = file.empty() ? read_file(platform::executable_path()) : read_file(platform::from_utf8(file));
        if (d.size && static_cast<std::int64_t>(data.size()) != *d.size) throw Failure("size mismatch: the file is not " + d.path);
        if (hex_sha256(data) != d.sha256) throw Failure("digest mismatch: the file is not " + d.path);
        std::printf("verified: %s is %s of CONVERGE v%s (signed manifest)\n", file.empty() ? "this executable" : file.c_str(), d.path.c_str(), manifest.version_text.c_str());
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "converge-bridge verify-release: %s\n", e.what());
        return 1;
    }
}

int setup(const std::vector<std::string>& args) {
    SetupArgs a;
    try {
        for (std::size_t i = 0; i < args.size(); ++i) {
            const auto& f = args[i];
            if (f == "--client" || f == "--skill-dir")
                throw Failure(f + " is gone: setup connects every supported AI client, installed or not yet (Claude Code, Codex, Copilot CLI, "
                              "Cursor CLI), each with its own skill directory. Run the same command without it.");
            else if (f == "--base") a.base = arg_value(args, i, f);
            else if (f == "--release-base") a.release_base = arg_value(args, i, f);
            else if (f == "--state-dir") a.state_dir = arg_value(args, i, f);
            else if (f == "--bridge") a.bridge = arg_value(args, i, f);
            else if (f == "--handle") a.handle = arg_value(args, i, f);
            else if (f == "--invite") a.invite = arg_value(args, i, f);
            else if (f == "--link") a.link = arg_value(args, i, f);
            else if (f == "--alias") a.alias = arg_value(args, i, f);
            // --host-name is what client 0.2.3 called it; still read, never shown.
            else if (f == "--peer-name" || f == "--host-name") a.peer_name = arg_value(args, i, f);
            else if (f == "--allow-tools") a.allow_tools = true;
            else if (f == "--disallow-tools") a.disallow_tools = true;
            else if (f == "--topic") a.topic = arg_value(args, i, f);
            else if (f == "--no-live-hook") a.no_live_hook = true;
            else if (f == "--remove-live-hook") a.remove_live_hook = true;
            else if (f == "--status") a.status = true;
            else if (f == "--help" || f == "-h") {
                std::printf("usage: converge-bridge setup [--base ORIGIN] [--release-base URL]\n"
                            "         [--state-dir DIR] [--bridge PATH] [--handle cvh_...]\n"
                            "         [--invite cvi_... [--alias NAME]] [--link cvi_...] [--peer-name NAME] [--topic TEXT] [--no-live-hook]\n"
                            "         [--remove-live-hook] [--allow-tools | --disallow-tools] [--status]\n");
                return 0;
            } else throw Failure("unknown option " + f);
        }
        return run_setup(a);
    } catch (const std::exception& e) {
        std::fprintf(stderr, "converge setup: %s\n", e.what());
        return 1;
    }
}

int serve(const std::vector<std::string>& args) {
    std::string state_dir;
    for (std::size_t i = 0; i < args.size(); ++i) {
        if (args[i] == "--state-dir" && i + 1 < args.size()) state_dir = args[++i];
        else { std::fprintf(stderr, "usage: converge-bridge serve --state-dir DIR\n"); return 2; }
    }
    const fs::path directory = state_dir.empty() ? platform::state_dir() : resolve_dir(state_dir);
    const auto state = read_json_object(directory / "setup.json");
    if (str(state, "handle").empty() || str(state, "bridge").empty()) {
        std::fprintf(stderr, "converge-bridge serve: setup is incomplete; run `converge-bridge setup --status` to see the next step.\n");
        return 1;
    }
    // stdout belongs exclusively to MCP. No credentials appear in process arguments, and none
    // are taken from the environment: the saved setup is the only source.
    BridgeOptions o;
    o.relay = str(state, "relay");
    o.pin_store = platform::to_utf8(directory / "known_peers");
    o.handle = str(state, "handle");
    o.identity_file = str(state, "identity_file");
    if (o.identity_file.empty()) o.identity_file = platform::to_utf8(directory / "identity");
    return run_bridge(o);
}

} // namespace converge::tools
