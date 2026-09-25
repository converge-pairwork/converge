// The bridge's subcommands: everything the AI session needs on the machine besides the MCP
// server itself, in the one executable, so a client machine needs nothing else installed.
//
//   converge-bridge setup ...          onboarding (the skill, the hook, the MCP registration)
//   converge-bridge serve --state-dir  the registered MCP server: the bridge with the saved setup
//   converge-bridge live               the host's PostToolUse hook: shows each exchange at once
//   converge-bridge update             the updater: signed manifest, digests, atomic install
//   converge-bridge verify-release     what the installer asks before it puts a download in place
//
// `converge-bridge --relay ... [auth]` without a subcommand is the bridge itself, unchanged.
#pragma once
#include <string>
#include <vector>

namespace converge::tools {

// The bridge's own command line, parsed. `serve` fills one from the saved setup.
struct BridgeOptions {
    std::string relay, handle, identity_file, pin_store, agent_pubkey;
    bool use_agent = false, print_identity = false;
    std::string alias, invite, link_code, relay_key;
    bool pair = false;
};
int run_bridge(const BridgeOptions& options);   // main.cpp

int setup(const std::vector<std::string>& args);
int serve(const std::vector<std::string>& args);
int live();
int update(const std::vector<std::string>& args);
int verify_release(const std::vector<std::string>& args);

} // namespace converge::tools
