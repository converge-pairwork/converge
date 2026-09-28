// The bridge's subcommands: everything the AI session needs on the machine besides the MCP
// server itself, in the one executable, so a client machine needs nothing else installed.
//
//   converge-bridge setup ...          onboarding (the skill, the hook, the MCP registration)
//   converge-bridge serve --state-dir  the registered MCP server: the bridge with the saved setup
//   converge-bridge live               the host's PostToolUse hook: shows each exchange at once
//   converge-bridge update             the updater: signed manifest, digests, atomic install
//   converge-bridge verify-release     what the installer asks before it puts a download in place
//   converge-bridge confirm CODE       confirms a wallet account's request to add this bridge
//   converge-bridge billing ...        reads or sets who this bridge offers to pay for
//
// `converge-bridge --relay ... [auth]` without a subcommand is the bridge itself, unchanged.
#pragma once
#include "relay_client.hpp"
#include <boost/json/object.hpp>
#include <cstdint>
#include <string>
#include <vector>

namespace converge::tools {

// The bridge's own command line, parsed. `serve` fills one from the saved setup.
struct BridgeOptions {
    std::string relay, handle, identity_file, pin_store, agent_pubkey;
    bool use_agent = false, print_identity = false;
    std::string alias, relay_key;
    std::int64_t installed_at = 0;
};
int run_bridge(const BridgeOptions& options);   // main.cpp

// Joins an invitation: one connection of its own with the join intent, whose welcome names this
// key's handle and the peer's, the one who made the invitation. Afterwards the two keys may call
// each other. Throws std::runtime_error with the relay's reason when it refuses.
struct Joined { std::string handle, peer_handle; };
Joined join_invite(const std::string& relay_url, Credentials creds, const std::string& pin_store, const std::string& code);

// A plain connection of its own, to be known to the relay and hear what it says about this key:
// its handle, the account it is on, and while that is its own, the link that adds it to a wallet's.
// `wallet`: the Solana address of the wallet whose account the bridge is on, "" while it is its own.
struct Introduced { std::string handle, wallet, pairing_link; std::uint64_t balance = 0; };
Introduced introduce(const std::string& relay_url, const Credentials& creds, const std::string& pin_store);

// Confirms a wallet account's request to add this bridge (the code the account was shown), on a
// connection of its own. Returns the wallet whose account the bridge is on now, and that account's
// balance; throws the relay's refusal.
struct Confirmed { std::string wallet; std::uint64_t balance = 0; };
Confirmed confirm_bridge(const std::string& relay_url, const Credentials& creds, const std::string& pin_store, const std::string& code);

// Reads or sets this bridge's payment preferences, on a connection of its own: for the bridge, or
// with `peer` for that one peer. Each value all, own, none, inherit, or keep (empty). Returns the
// preferences as the relay states them afterwards; throws its refusal.
boost::json::object billing_prefs(const std::string& relay_url, const Credentials& creds, const std::string& pin_store,
                                  const std::string& peer, const std::string& as_caller, const std::string& as_callee);

// What this bridge says about itself when it connects (Credentials::version and on), and when it
// was installed: setup.json's installed_at, else the identity key's age, else 0.
void describe_bridge(Credentials& creds, std::int64_t installed_at);
std::int64_t installed_at(const boost::json::object& setup_state, const std::string& identity_file);

int setup(const std::vector<std::string>& args);
int confirm(const std::vector<std::string>& args);
int billing(const std::vector<std::string>& args);
int serve(const std::vector<std::string>& args);
int live();
int update(const std::vector<std::string>& args);
int verify_release(const std::vector<std::string>& args);

} // namespace converge::tools
