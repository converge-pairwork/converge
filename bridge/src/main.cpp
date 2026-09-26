// converge-bridge, MCP stdio server that connects this AI session to a coworker's
// through the Converge relay. With a subcommand it is the rest of what a client machine needs
// (tools.hpp): setup, serve, live, update, verify-release.
#include "identity.hpp"
#include "handshake.hpp"
#include "mcp.hpp"
#include "platform.hpp"
#include "tools.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>

namespace {
const char* env_or(const char* name, const char* def) {
    const char* v = std::getenv(name);
    return v && *v ? v : def;
}
void usage() {
    std::fprintf(stderr,
        "usage: converge-bridge --relay wss://host/link [options]\n"
        "       converge-bridge setup [options]      onboard this AI session (see setup --help)\n"
        "       converge-bridge serve --state-dir D  the MCP server setup registered\n"
        "       converge-bridge live                 the host's PostToolUse hook (reads the event on stdin)\n"
        "       converge-bridge update [--force]     check for and install a newer release\n"
        "       converge-bridge verify-release --release URL --file PATH\n"
        "\n"
        "identity (the way in: a key of this machine's own, never a secret on the wire):\n"
        "  --identity-file PATH     ed25519 key, generated on first use (default ~/.converge/identity)\n"
        "  --handle cvh_...         the handle this key is known by (informational; the relay derives it)\n"
        "  --ssh-agent [PUBKEY]     sign via $SSH_AUTH_SOCK instead of a file\n"
        "  --print-identity         print this bridge's public key line, address and handle, and exit\n"
        "  --alias NAME             what to call this key on its own account (default self)\n"
        "  --invite cvi_...         redeem a host-paid invitation: become a member of the inviter's account\n"
        "  --link cvi_...           link a split invitation: introduce your account and the inviter's\n"
        "  --pair                   wait until a wallet approves this key at the site's pairing link\n"
        "  --relay-key ADDRESS      the relay's key (else pinned on first use)\n"
        "\n"
        "other:\n"
        "  --pin-store PATH         known peer identities (default ~/.converge/known_peers)\n"
        "\n"
        "env: CONVERGE_RELAY, CONVERGE_HANDLE, CONVERGE_ALIAS, CONVERGE_RELAY_KEY\n");
}
} // namespace

namespace converge::tools {

int run_bridge(const BridgeOptions& o) {
    std::string pin_store = o.pin_store;
    if (pin_store.empty()) pin_store = platform::to_utf8(platform::state_dir() / "known_peers");
    std::string identity_file = o.identity_file.empty() ? default_identity_path() : o.identity_file;

    // The identity is the way in: a key on its own is its own account, until a certificate or an
    // invitation says otherwise.
    std::string err;
    std::unique_ptr<Signer> signer = o.use_agent ? make_agent_signer(o.agent_pubkey, &err) : make_file_signer(identity_file, true, &err);
    if (!signer) { std::fprintf(stderr, "converge-bridge: %s\n", err.c_str()); return 1; }
    if (o.print_identity) {
        // The public half only: the ssh line, and the same key as a Solana address, which is what
        // a certificate names and what the pairing link carries.
        // stdout is the one line (setup and scripts read it); the address and handle go to stderr.
        auto parsed = parse_ssh_ed25519(signer->public_ssh_line());
        std::printf("%s\n", signer->public_ssh_line().c_str());
        if (parsed) std::fprintf(stderr, "address: %s\nhandle: %s\n", link::identity_text(parsed->raw).c_str(), link::handle_of(parsed->raw).c_str());
        return 0;
    }

    Credentials creds;
    creds.handle = o.handle;
    creds.alias = o.alias; creds.relay_key = o.relay_key;
    const std::string identity_line = signer->public_ssh_line();
    auto parsed = parse_ssh_ed25519(identity_line);
    if (!parsed) { std::fprintf(stderr, "converge-bridge: the identity is not an ed25519 key\n"); return 1; }
    creds.identity = parsed->raw;
    if (!o.invite.empty()) { creds.intent = 1; creds.invite_code = o.invite; }
    else if (!o.link_code.empty()) { creds.intent = 2; creds.invite_code = o.link_code; }
    else if (o.pair) creds.intent = 3;
    std::fprintf(stderr, "[converge-bridge] identity %s (handle %s) via %s\n", link::identity_text(parsed->raw).c_str(),
                 link::handle_of(parsed->raw).c_str(), signer->describe().c_str());
    creds.sign = [s = signer.get()](std::string_view m) { return s->sign(m); };

    try {
        Bridge::Signer sign = [s = signer.get()](std::string_view m) { return s->sign(m); };
        Bridge b(o.relay, std::move(creds), pin_store, identity_line, std::move(sign));
        return b.serve_stdio();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "converge-bridge: fatal: %s\n", e.what());
        return 1;
    }
}

} // namespace converge::tools

int main(int argc, char** argv) {
    // A subcommand is a word, not an option; everything after it belongs to it.
    if (argc > 1 && argv[1][0] != '-') {
        const std::string sub = argv[1];
        std::vector<std::string> rest(argv + 2, argv + argc);
        if (sub == "setup") return converge::tools::setup(rest);
        if (sub == "serve") return converge::tools::serve(rest);
        if (sub == "live") return converge::tools::live();
        if (sub == "update") return converge::tools::update(rest);
        if (sub == "verify-release") return converge::tools::verify_release(rest);
        if (sub == "version") { std::printf("%s\n", CONVERGE_VERSION); return 0; }
        usage();
        return 2;
    }

    converge::tools::BridgeOptions o;
    // The canonical public service, and the only default. Setup always passes --relay itself,
    // so this value matters only to someone running the bridge by hand.
    o.relay = env_or("CONVERGE_RELAY", "wss://converge.pairwork.net/link");
    o.handle = env_or("CONVERGE_HANDLE", "");
    // What this key wants to be on the relay.
    o.alias = env_or("CONVERGE_ALIAS", "");
    o.relay_key = env_or("CONVERGE_RELAY_KEY", "");

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
        if (a == "--relay") o.relay = next();
        else if (a == "--handle") o.handle = next();
        else if (a == "--identity-file") o.identity_file = next();
        else if (a == "--pin-store") o.pin_store = next();
        else if (a == "--ssh-agent") {
            o.use_agent = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') o.agent_pubkey = next();
        } else if (a == "--print-identity") o.print_identity = true;
        else if (a == "--alias") o.alias = next();
        else if (a == "--invite") o.invite = next();
        else if (a == "--link") o.link_code = next();
        else if (a == "--pair") o.pair = true;
        else if (a == "--relay-key") o.relay_key = next();
        else if (a == "--version") { std::printf("%s\n", CONVERGE_VERSION); return 0; }
        else { usage(); return a == "--help" ? 0 : 2; }
    }
    return converge::tools::run_bridge(o);
}
