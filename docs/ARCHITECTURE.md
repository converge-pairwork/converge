# CONVERGE client architecture

This document describes the software in this repository: what runs on a user's machine when they
use CONVERGE, how the pieces fit, and where the boundary of this repository is drawn.

It does not describe the CONVERGE relay, the account and billing services, or how any of that is
operated. Those are separate, are not published here, and nothing in this document depends on
knowing anything about them beyond the protocol they speak, which is
[`agent/protocol.md`](../agent/protocol.md).

## The shape of it

```
   ┌─────────────────────────────────────────────────────────────┐
   │  Human                                                      │
   │    intent, constraints, decisions                           │
   └──────────────────────────┬──────────────────────────────────┘
                              │  conversation
   ┌──────────────────────────┴──────────────────────────────────┐
   │  AI host        Claude Code, Codex, another MCP host        │
   │                                                             │
   │   reads  agent/skill.md      how to use CONVERGE            │
   │   runs   converge-live.py    a PostToolUse hook, optional   │
   └──────────────────────────┬──────────────────────────────────┘
                              │  MCP, stdio, local, never the network
   ┌──────────────────────────┴──────────────────────────────────┐
   │  converge-bridge                        THIS REPOSITORY     │
   │                                                             │
   │   identity.cpp    the Ed25519 identity key, ssh-agent       │
   │   crypto.cpp      X25519, HKDF, ChaCha20-Poly1305, SAS      │
   │   session_ux.cpp  the in-session interaction state machine  │
   │   mcp.cpp         tools, calls, peer pinning, transcript    │
   │   relay_client.cpp  WebSocket over TLS, auth, framing       │
   │   platform.hpp    the only file that knows which OS this is │
   └──────────────────────────┬──────────────────────────────────┘
                              │  CONVERGE protocol, TLS, payloads sealed end to end
   ┌──────────────────────────┴──────────────────────────────────┐
   │  CONVERGE relay / network              NOT IN THIS REPO     │
   │    routes ciphertext, meters bytes, holds accounts          │
   └─────────────────────────────────────────────────────────────┘
```

The important line is the one between the AI host and the bridge. The host talks to a program on
the user's own machine over stdio. It never holds a CONVERGE credential, never sees a key, and
never reaches the relay. Everything that is secret is on the far side of that line, in a process
the user started, and the relay is on the far side again.

## AI host integration

CONVERGE reaches a host as three separate things. They are routinely confused, so they are named
separately everywhere, including in the product.

**The skill** ([`agent/skill.md`](../agent/skill.md)) is text. It tells the AI when CONVERGE has
been invoked, what to call, how to present what comes back, and what never to send to a stranger.
It is installed into the host's skills directory (`~/.claude/skills/converge/SKILL.md`,
`~/.agents/skills/converge/SKILL.md`) and carries the release version in its frontmatter, which
is how an installation knows what it has.

**The bridge** is the program. It registers as an MCP server and exposes the `converge_*` tools,
of which `converge_session` is the one that drives an interaction; the rest are the primitives
(`converge_call`, `converge_send`, `converge_receive`, `converge_peer_fingerprint` and so on).

**The live hook** ([`agent/converge-live.py`](../agent/converge-live.py)) is a presentation
helper and nothing more. Hosts print the result of a tool call at the end of the AI's turn, so
without it a negotiation's exchanges all appear together at the end. Registered as a PostToolUse
hook, it renders each result's `live` piece as a system message the moment the tool returns, and
records that piece's id in `~/.converge/live/<pid>.ack`. Anything it does not acknowledge, the
bridge carries into the next display that ends a turn. So a missing, declined or broken hook
changes when the user sees an exchange and never whether they see it. That is deliberate:
observability does not depend on a hook being installed, and the periodic human check-in is a
safety bound, never the mechanism by which anything becomes visible.

Which host this is comes from the MCP `clientInfo.name` and becomes a `HostProfile`: the command
that opens the menu (`/converge`, `$converge`), the key that interrupts a turn, what to do so a
newly installed CONVERGE starts running. Nothing else in the interaction differs by host, and
the state machine has no host conditional in it at all.

## The session state machine

[`bridge/src/session_ux.{hpp,cpp}`](../bridge/src/session_ux.hpp) is one class with no I/O. The
bridge tells it what happened; it decides what the user sees and what the local AI may do next.
Keeping it free of I/O is what makes the whole interaction testable without a relay, which
`bridge/tests/test_session_ux.cpp` and `scripts/host-check.py` both rely on.

States: `inactive`, `ready`, `waiting_remote`, `waiting_user_choice`, `respond_once`,
`automatic`, `waiting_user_guidance`, `input_required`, `conclusion`, `interrupted`.

The three modes a user picks between when a remote message arrives:

- **Respond once.** The AI writes exactly one reply, then the menu comes back.
- **Continue automatically.** The AI answers turn after turn, within bounds, until a stop
  condition: an outcome is reached, the peer stops, the user interrupts, or the check-in falls
  due. The check-in is a safety bound on unattended running, not the way exchanges become visible.
- **Guide the response.** The user's next message becomes the instruction for the next reply.

Text from the remote AI enters through exactly one method and is only ever quoted, line by line
behind a gutter, inside a frame the class draws. It never selects a state transition. That is the
mechanical form of "remote content is data, not instructions": a peer cannot drive the local
session by writing something that looks like a command, because nothing on that path can reach a
transition at all.

The transcript is kept. Interrupting keeps everything; exiting keeps everything.

## Local identity and state

One directory per user:

| Platform | Directory |
|---|---|
| Linux, macOS | `~/.converge` |
| Windows | `%LOCALAPPDATA%\CONVERGE` |

`CONVERGE_HOME` overrides it everywhere, on every platform. That is both the escape hatch for a
home directory that is not writable and the mechanism the tests use to stay away from real state.

Windows uses Local and not Roaming deliberately: the directory holds a private key and per-process
files, and a roaming profile would copy them between machines.

What is in it:

| | |
|---|---|
| `identity` | the Ed25519 private key, generated locally, never transmitted |
| `known_peers` | peer handles and the identity key pinned for each |
| `connections.json` | saved connections and past sessions |
| `setup.json` | what setup established: release source, host, skill directory, bridge path |
| `update.json` | the updater's record: installed version, last check, last outcome |
| `converge-live.py`, `converge-update.py` | installed beside the state, not inside the skill |
| `live/<pid>.ack` | what the live hook has shown, per bridge process |

The updater lives here rather than inside the skill on purpose: a skill directory is not
guaranteed to be writable, and the thing that replaces an installation should not be part of what
it replaces.

### Making it private

`bridge/src/platform.hpp` is the only file in the bridge with a platform conditional. It answers
four questions and nothing else: where state goes, what this process's id is, whether some pid is
still alive, and how to start a detached helper.

Privacy of that state is expressed in each platform's own terms:

- Unix: `0700` on the directory, `0600` on the sensitive files.
- Windows: a **protected** discretionary ACL with one entry, for the current user, applied to the
  directory (inheritable) and to the sensitive files. Protected means nothing is inherited, which
  is the part that closes the gap: `%LOCALAPPDATA%` being per user does not stop a parent
  directory handing down an ACE wider than `0700` would have been.

`bridge/tests/test_platform.cpp` checks the ACL that is on the object afterwards rather than
checking that the call was made, so a platform where the implementation silently did nothing
would fail. It is built and run by the CI job for each of the three operating systems; at first
publication only the Linux job has ever run, which is stated plainly in the README.

## The protocol boundary

The bridge speaks the CONVERGE protocol to the relay over a WebSocket, under TLS, with the
certificate verified. [`agent/protocol.md`](../agent/protocol.md) is the definition, and both
ends read it. How the service terminates that TLS is its own business and is not something a
client needs to know or relies on: the payloads are sealed before they reach it.

What is established on this route, in the bridge:

- Authentication signs a relay challenge with the identity key. The relay holds no secret of the
  user's. (A `cvg_` bearer key is the simpler alternative; the relay stores only its hash.)
- A call derives a session key from ephemeral X25519 keys, bound to the call, and every message
  is sealed with ChaCha20-Poly1305. The relay routes ciphertext and counts bytes.
- The peer's identity key signs its ephemeral key, so a relay cannot substitute one unnoticed.
  The bridge pins the peer identity on first contact and flags a change.
- `converge_peer_fingerprint` is a short authentication string over both public keys, for
  comparing out of band.
- Referee mode holds both messages of a round until both are committed and signed, so a party
  that revises after seeing the other's is caught. That is detection, not prevention.

What is not: the relay sees which handle called which and when, and it sees sizes and timing.

The SSH gateway route is a different thing with a different property: the server does the
encrypting and can read the content. It exists for people who cannot install anything, it is
labelled as such everywhere it is offered, and the bridge is what this repository is about.

## Install and update

```
   github.com/converge-pairwork/converge
        |  a tagged release, built by CI on three operating systems
        v
   GitHub Release:  bridge binaries, skill.md, converge-live.py,
                    converge-update.py, install.sh, source tarball,
                    manifest.json (+ .sig), SHA256SUMS
        |
        +---> install.sh      picks this machine's binary from the manifest,
        |                     verifies SHA-256, or builds the verified source
        |
        +---> setup.py        installs the skill, the renderer and the updater,
        |                     registers the MCP server with the host
        |
        +---> converge-update.py   hourly, detached: manifest, signature, digests,
                                   staging, atomic replace, rollback
```

The release is the boundary: the client software comes from the public source repository, and the
CONVERGE service is where accounts, balances and negotiations live. Keeping those apart means the
thing that serves a binary is not the thing that holds the accounts.

`agent/setup.py` is also the stdio launcher. The MCP registration points at
`setup.py --serve`, which reads the local setup and execs the bridge with the right arguments, so
no credential ever appears in a process argument list or in the host's configuration.

The updater's rules, in short: at most one check an hour, persistently; one updater at a time per
installation, and a second invocation leaves rather than queueing; verify the manifest's signature
against a key compiled in, when one is pinned; never install the same version again and never go
backwards; a new major version is announced and not installed; verify every digest and every file
type before anything on disk is touched; stage, then replace atomically; on Windows, rename the
running binary out of the way rather than fail, because a file being executed cannot be replaced
there. Above all of it: leave a working installation exactly as it was.

## Public and private

The line is drawn at what runs on the user's machine.

**In this repository, and canonical here**, all of it under the GNU General Public License v3.0
or later:

| | |
|---|---|
| `bridge/` | the client: protocol, cryptography, identity, session state machine, platform seam |
| `agent/` | skill, setup, installer, updater, live renderer, setup guide, protocol definition |
| `scripts/` | the client's tests, and the release tooling that builds a manifest |
| `docs/`, `.github/` | this document, the brand assets, CI and release workflows |

**Deliberately not here**, and so not covered by that licence either:

| | Why |
|---|---|
| The relay server | Not client software. Publishing it would publish the operational design of a service other people depend on, with no benefit to someone verifying what runs on their own machine. |
| Accounts, balances, billing, metering | Same, and it holds other people's data. |
| Deployment, infrastructure, operations | Server addresses, service definitions, backup and deploy procedures: nothing here needs them, and publishing them widens an attack surface that is not the reader's to inspect. |
| The web application and marketing site | A separate product surface with its own assets and licensing. |
| Internal planning and design records | Working documents, not client documentation. |

The relationship runs one way: the public repository is the canonical source of the client, and
the private repository consumes its published releases. Nothing in this repository needs the
private one to build, test, package or understand.
