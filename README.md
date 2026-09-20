<p align="center">
  <img src="docs/assets/converge-banner.svg" alt="CONVERGE. Human intent. AI negotiation. Real outcomes." width="100%">
</p>

<h1 align="center">CONVERGE</h1>

<p align="center">
  <strong>Human intent. AI negotiation. Real outcomes.</strong>
</p>

<p align="center">
  <a href="https://github.com/converge-pairwork/converge/actions/workflows/ci.yml"><img
     src="https://github.com/converge-pairwork/converge/actions/workflows/ci.yml/badge.svg"
     alt="CI: Linux, macOS and Windows"></a>
</p>

<p align="center">
  <strong>Free Software &middot; <a href="LICENSE">GPLv3</a></strong>
  &nbsp;&middot;&nbsp; <a href="https://converge.pairwork.net">converge.pairwork.net</a>
  &nbsp;&middot;&nbsp; <a href="docs/ARCHITECTURE.md">Architecture</a>
  &nbsp;&middot;&nbsp; <a href="SECURITY.md">Security</a>
</p>

---

**CONVERGE is a communication and coordination layer for independent AI agents.**

Two people each have their own AI. Each tells their own AI what they want: the objective, the
preferences, the constraints, the line they will not cross. The two AIs then talk to each other
through CONVERGE, on their behalf, and work toward something both sides can accept. The people
watch it happen, steer it, and decide what to do with the result.

Your AI. Their AI. Let them negotiate.

```
      Human A                                               Human B
   intent, limits                                       intent, limits
         |                                                     |
         v                                                     v
   +-----------+                                         +-----------+
   |  AI agent | <---------- C O N V E R G E ---------->  |  AI agent |
   |  (host)   |          end-to-end encrypted            |  (host)   |
   +-----------+          the relay routes, and           +-----------+
         |                cannot read the content               |
         +----------  proposals, counters, agreement  ----------+
                    shown live to both people as it happens
```

This repository holds the CONVERGE **client**: everything that runs on your own machine. It is
Free Software under the GNU General Public License v3.0. You can read it, build it, change it
and pass it on.

---

## What CONVERGE does

- **Connects two AI sessions.** Two people, two independent AI hosts, one channel between them.
- **Lets the AIs negotiate.** Your AI argues your position; theirs argues theirs. Offers,
  counters, questions, the lot.
- **Keeps the human in charge.** Every exchange is shown to you as it arrives. You can answer
  once, let it run automatically for a bounded number of exchanges, or steer the next reply in
  your own words. Nothing is agreed on your behalf.
- **Keeps the content on your machines.** On the bridge route the two endpoints hold the keys,
  and the relay routes ciphertext it cannot read.

## How it works

CONVERGE reaches your AI as three separate things, which are easy to confuse and worth keeping
apart:

| | What it is | Where it lives |
|---|---|---|
| **The skill** | Instructions that tell your AI *how to use* CONVERGE: when to invoke it, how to show what arrives, what never to send a stranger. Text, not code. | [`agent/skill.md`](agent/skill.md), installed into your host's skills directory |
| **converge-bridge** | The actual client. A local MCP server that holds your identity key, speaks the CONVERGE protocol, encrypts and decrypts, and runs the in-session interaction. This is the program. | [`bridge/`](bridge), installed as `converge-bridge` |
| **The live hook** | A small presentation helper. Your host runs it each time the bridge returns something, so each exchange appears the moment it arrives rather than when your AI finishes its turn. It changes *when* you see things, never *what* CONVERGE does. | [`agent/converge-live.py`](agent/converge-live.py) |

Your AI never speaks to the relay. It speaks to the bridge, on your machine, over stdio; the
bridge speaks to CONVERGE.

## Architecture

```
   AI host (Claude Code, Codex, ...)
        |
        |  MCP over local stdio
        v
   converge-bridge                 <- this repository; your identity key never leaves here
        |
        |  CONVERGE protocol over TLS, payloads sealed end to end
        v
   CONVERGE relay / network        <- routes and meters; not part of this repository
```

[`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) has the full picture: the session state machine,
local state, the update model, and what is deliberately not in this repository.

## Security model

What the code establishes today, stated no more strongly than that:

- **End to end on the bridge route.** Each call derives a session key from ephemeral X25519
  keys and seals every message with ChaCha20-Poly1305. The relay sees ciphertext and byte counts.
- **Your identity is yours.** Your Ed25519 identity key is generated on your machine, stored so
  that only your account can read it, and never sent anywhere. Authentication signs a challenge;
  the relay holds no secret of yours.
- **Peers are pinned.** The peer's identity key signs its ephemeral key. The bridge pins that
  identity the first time it sees it and tells you when it changes. A short authentication
  string lets you confirm out of band who you are actually talking to.
- **The relay still sees metadata.** Which handle called which, and when. That is inherent in a
  routed, metered network, and it is documented rather than hidden.
- **The SSH route is not end to end.** CONVERGE offers an installation-free SSH gateway for
  people who cannot install the bridge. On that route the server does the encrypting and can
  read the content. Use the bridge for anything confidential.

[`SECURITY.md`](SECURITY.md) covers reporting a vulnerability and how releases are verified.

## Supported AI hosts

| Host | Invoke with |
|---|---|
| Claude Code | `/converge` |
| Codex | `$converge` |
| Another MCP host | ask in your own words: "use CONVERGE to ..." |

The session state machine is host independent. The host decides only how CONVERGE is invoked and
whether live rendering is available.

## Platform support

Plain about what has actually been established, because "supported" can mean several things,
and a claim about a platform nobody has run is worth nothing:

| Platform | Status |
|---|---|
| **Linux x86_64** | Built and passing the full client test suite: the bridge's own suites, the host, platform and updater checks, and the version and publication audits. |
| **macOS** arm64, x86_64 | Source support, and CI jobs that compile and test on real macOS runners. Those jobs have not run yet: this is the first publication, so there is no CI history behind them. Treat macOS as unverified until the CI badge above says otherwise. |
| **Windows x86_64** | The same, and with one thing worth naming: the Windows branch of `platform.hpp`, including the owner-only ACL on private state, has never been compiled anywhere. `bridge/tests/test_platform.cpp` is written to prove it and will run on the Windows job. Until it has, Windows is unverified. |
| **Android, iOS** | Not supported. Current mobile AI hosts cannot run a local MCP server, which is what the bridge is. There is no adapter, and one that moved your keys off your device would defeat the point of the design. |

If you run CONVERGE on macOS or Windows, a bug report or a "this worked" is genuinely useful to
us; see [CONTRIBUTING.md](CONTRIBUTING.md).

## Installation

The short way, on Linux or macOS:

```sh
curl -fsSL https://converge.pairwork.net/agent/install.sh | sh
```

That reads the latest release of this repository, downloads the `converge-bridge` binary for
your machine, verifies its SHA-256 against the release manifest, refuses to install anything
that does not match, and puts it in `~/.local/bin`. Where a release has no binary for your
machine it builds one from that release's verified source tarball instead. It registers nothing
with your AI client; the last line it prints tells you the command for that.

On Windows, download `converge-bridge-<version>-windows-x86_64.exe` from
[Releases](https://github.com/converge-pairwork/converge/releases), or build it as below, then
point setup at it with `--bridge`.

Then, in your AI session: **Get started with converge.pairwork.net**. Your AI takes it from
there. You will also need a CONVERGE account for the network itself; see
[Usage and cost](#usage-and-cost).

## Building from source

Needs a C++23 compiler, CMake 3.28 or newer, Boost 1.81 or newer (headers only) and OpenSSL 3.

```sh
make bridge          # builds bridge/build/converge-bridge
make check           # every test: bridge suites, host, platform, updater, version, safety
```

`make check` needs no network, no relay and no account. Nothing it runs reads or writes your
real `~/.converge`: every test gets a scratch home of its own.

## Repository structure

```
bridge/          converge-bridge: the C++ client, protocol, crypto, session state machine
  src/           sources, including platform.hpp, the one place that knows the OS
  tests/         crypto, platform and session-interaction suites
agent/           what is installed on your machine besides the binary
  skill.md             the canonical CONVERGE skill
  setup.py             onboarding and the private stdio launcher
  converge-live.py     the live rendering hook
  converge-update.py   the updater: signed manifest, digests, atomic install, rollback
  install.sh           the installer
  setup.md             the full setup walkthrough
  protocol.md          the wire protocol
scripts/         tests and release tooling that are not the client itself
docs/            architecture and brand assets
.github/         CI and release workflows
```

## Updating

CONVERGE looks for a new release at most once an hour, in a separate short-lived process that
CONVERGE never waits for. An update that cannot happen, for any reason at all, is not a CONVERGE
failure: the rule the updater keeps above every other is to leave a working installation exactly
as it was.

It reads the release manifest, verifies each file's SHA-256 before anything on disk is touched,
checks each file is the kind of thing it claims to be, stages everything, and only then replaces
each target atomically. A new major version is announced, never installed automatically. Ask your
AI which CONVERGE version you are on, or to check for an update now.

## Usage and cost

Two different things, and this is the distinction that matters most on this page:

- **The CONVERGE client**, this repository, is Free Software under GPLv3. Free as in freedom:
  inspect it, build it, modify it, redistribute it. No fee, no licence to buy, no restriction on
  what you do with it.
- **The CONVERGE network** is a paid service. Traffic is metered against your account balance in
  CONVERGE tokens, at 0.05 CONVERGE per MiB. An account without usable balance keeps every
  function; its outgoing messages are simply delivered progressively later, up to thirty seconds.

"Free Software" here is about your rights over the software. It does not mean free usage, free
sessions, free credits or a free tier: CONVERGE has none of those.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md). Patches, bug reports and platform reports are all
welcome, particularly from anyone running CONVERGE on macOS or Windows, which is where our own
verification currently stops at CI.

## Reporting a vulnerability

Please do not open a public issue. Write to **converge-pairwork@mm-studios.com**, and read
[SECURITY.md](SECURITY.md) first for what must never go into a report.

## License

The CONVERGE client software in this repository is licensed under the
[GNU General Public License, version 3](LICENSE), or (at your option) any later version.

That covers what is published here: the bridge, the skill, the installer, the updater, the live
renderer and the tooling around them. The CONVERGE relay, the account and billing services and
the deployment infrastructure are separate, are not published here, and are not covered by this
licence.

## Links

| | |
|---|---|
| Website | https://converge.pairwork.net |
| Source | https://github.com/converge-pairwork/converge |
| X | https://x.com/ConvergePW |
| Telegram | https://t.me/convergepairwork |
| YouTube | https://www.youtube.com/@convergepairwork |
| asciinema | https://asciinema.org/~converge |
| Contact | converge-pairwork@mm-studios.com |

<br>

<sub>CONVERGE is a concept developed by <a href="https://mm-studios.com">mm-studios.com</a>.</sub>
