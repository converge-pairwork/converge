// converge-bridge, MCP stdio server that connects this AI session to a coworker's
// through the Converge relay.
#include "identity.hpp"
#include "handshake.hpp"
#include "mcp.hpp"
#include "platform.hpp"

#include <cstdio>
#include <cstdlib>
#include <string>

namespace {
const char* env_or(const char* name, const char* def) {
    const char* v = std::getenv(name);
    return v && *v ? v : def;
}
void usage() {
    std::fprintf(stderr,
        "usage: converge-bridge --relay wss://host/v1/ws [auth] [options]\n"
        "\n"
        "auth (pick one):\n"
        "  --key cvg_...            bearer key (simple; the relay stores only its hash)\n"
        "  --handle cvh_...         identity-key auth: signs a challenge, no secret is sent\n"
        "\n"
        "identity options (with --handle):\n"
        "  --identity-file PATH     ed25519 key, generated on first use (default ~/.converge/identity)\n"
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
        "env: CONVERGE_RELAY, CONVERGE_KEY, CONVERGE_HANDLE\n");
}
} // namespace

int main(int argc, char** argv) {
    // The canonical public service, and the only default. setup.py always passes --relay
    // itself, so this value matters only to someone running the bridge by hand.
    std::string relay = env_or("CONVERGE_RELAY", "wss://converge.pairwork.net/v1/ws");
    std::string key = env_or("CONVERGE_KEY", env_or("CONVERGE_TOKEN", ""));
    std::string handle = env_or("CONVERGE_HANDLE", "");
    std::string identity_file = converge::default_identity_path();
    std::string pin_store, agent_pubkey;
    bool use_agent = false, print_identity = false;
    // v4: what this key wants to be on the relay.
    std::string alias = env_or("CONVERGE_ALIAS", ""), invite, link_code, relay_key = env_or("CONVERGE_RELAY_KEY", "");
    bool pair = false;

    for (int i = 1; i < argc; ++i) {
        std::string a = argv[i];
        auto next = [&]() -> std::string { return i + 1 < argc ? argv[++i] : ""; };
        if (a == "--relay") relay = next();
        else if (a == "--key" || a == "--token") key = next();
        else if (a == "--handle") handle = next();
        else if (a == "--identity-file") identity_file = next();
        else if (a == "--pin-store") pin_store = next();
        else if (a == "--ssh-agent") {
            use_agent = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') agent_pubkey = next();
        } else if (a == "--print-identity") print_identity = true;
        else if (a == "--alias") alias = next();
        else if (a == "--invite") invite = next();
        else if (a == "--link") link_code = next();
        else if (a == "--pair") pair = true;
        else if (a == "--relay-key") relay_key = next();
        else { usage(); return a == "--help" ? 0 : 2; }
    }
    if (pin_store.empty()) pin_store = converge::platform::to_utf8(converge::platform::state_dir() / "known_peers");

    std::unique_ptr<converge::Signer> signer;
    // The identity is the default way in (protocol v4): a key on its own is its own account. A
    // bearer key (--key) is the old way, kept for members made before v4.
    if (print_identity || key.empty()) {
        std::string err;
        signer = use_agent ? converge::make_agent_signer(agent_pubkey, &err)
                           : converge::make_file_signer(identity_file, true, &err);
        if (!signer) { std::fprintf(stderr, "converge-bridge: %s\n", err.c_str()); return 1; }
    }
    if (print_identity) {
        // The public half only: the ssh line, and the same key as a Solana address, which is what
        // a certificate names and what the pairing link carries.
        // stdout is the one line (setup and scripts read it); the address and handle go to stderr.
        auto parsed = converge::parse_ssh_ed25519(signer->public_ssh_line());
        std::printf("%s\n", signer->public_ssh_line().c_str());
        if (parsed) std::fprintf(stderr, "address: %s\nhandle: %s\n", converge::link::identity_text(parsed->raw).c_str(), converge::link::handle_of(parsed->raw).c_str());
        return 0;
    }

    converge::Credentials creds;
    creds.key = key;
    creds.handle = handle;
    creds.alias = alias; creds.relay_key = relay_key;
    std::string identity_line;
    if (key.empty()) {
        identity_line = signer->public_ssh_line();
        auto parsed = converge::parse_ssh_ed25519(identity_line);
        if (!parsed) { std::fprintf(stderr, "converge-bridge: the identity is not an ed25519 key\n"); return 1; }
        creds.identity = parsed->raw;
        if (!invite.empty()) { creds.intent = 1; creds.invite_code = invite; }
        else if (!link_code.empty()) { creds.intent = 2; creds.invite_code = link_code; }
        else if (pair) creds.intent = 3;
        std::fprintf(stderr, "[converge-bridge] identity %s (handle %s) via %s\n", converge::link::identity_text(parsed->raw).c_str(),
                     converge::link::handle_of(parsed->raw).c_str(), signer->describe().c_str());
        creds.sign = [s = signer.get()](std::string_view m) { return s->sign(m); };
    } else if (!handle.empty()) {
        std::fprintf(stderr, "[converge-bridge] --key given: the old protocol; --handle is ignored\n");
        creds.handle.clear();
    }

    try {
        converge::Bridge::Signer sign;
        if (signer) sign = [s = signer.get()](std::string_view m) { return s->sign(m); };
        converge::Bridge b(relay, std::move(creds), pin_store, identity_line, std::move(sign));
        return b.serve_stdio();
    } catch (const std::exception& e) {
        std::fprintf(stderr, "converge-bridge: fatal: %s\n", e.what());
        return 1;
    }
}
