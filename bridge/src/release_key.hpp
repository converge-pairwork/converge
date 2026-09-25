// The public halves of the keys a CONVERGE release manifest may be signed with, base64 of the
// raw 32 bytes, newest first. They are here, in the code, and never taken from a manifest, a
// server or a setting: a key an attacker can supply is not a key.
//
// A release manifest must carry a signature that verifies against one of these; an unsigned or
// wrongly signed manifest is refused outright, whoever served it. Rotation is adding the new
// key in front and leaving the old one until installations have moved.
//
// The key below is the production CONVERGE release-signing key, whose fingerprint is
// SHA256:cdd8d54f 0c027837 f387bcfa 0536c738 2b49acd7 43966ad9 7d98dbaa 99555ae8. Its private
// half is held by the project owner, offline, and is not in this repository, not in GitHub
// Actions, not in a repository secret and not on any machine that serves releases.
//
// scripts/release-test.py reads this file and refuses a tree whose key is not a well formed
// point on the curve, so a stand-in cannot quietly become something installations trust.
#pragma once

namespace converge::release {

inline constexpr const char* keys[] = {
    "6STokPtBRPz4vlJ8C/n1yb8MD47bXYQz+x7mhUJLxTs=",
};

} // namespace converge::release
