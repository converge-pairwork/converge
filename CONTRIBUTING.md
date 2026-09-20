# Contributing to CONVERGE

Thank you for looking. CONVERGE is a small project and a patch that arrives with a test and a
clear reason is genuinely welcome.

## Before anything else

**Security problems do not go here.** If you have found something that looks like a
vulnerability, read [SECURITY.md](SECURITY.md) and write to converge-pairwork@mm-studios.com.
A public issue is a disclosure.

**Never put credentials or real negotiation content in an issue, a pull request, a test fixture
or a log excerpt.** Not your identity key, not a `cvg_` key, not a wallet seed phrase, not
somebody else's handle, and not the text of a real negotiation. Reproduce with invented data.

## What is in this repository

The CONVERGE **client**: the bridge, the skill, the installer, the updater, the live renderer,
and the tests and release tooling around them. The relay, the account and billing services and
the deployment infrastructure are not here, so a change that needs a running relay is one we
will have to exercise on our side.

Everything in [`make check`](Makefile) runs without a network, a relay or an account.

## Getting set up

```sh
make bridge          # needs a C++23 compiler, CMake 3.28+, Boost 1.81+ headers, OpenSSL 3
make check           # the whole suite; a few minutes
```

If `make check` passes on your machine before your change and after it, you are most of the way
to a reviewable pull request.

## Testing expectations

A change to behaviour comes with a test that fails without it. The suites are organised by the
question they answer, and a new test usually belongs in one of these:

| | |
|---|---|
| `bridge/tests/test_crypto.cpp` | sealing, key derivation, replay, encodings |
| `bridge/tests/test_platform.cpp` | where private state goes on each OS, and whether it is private there |
| `bridge/tests/test_session_ux.cpp` | the in-session interaction: banner, framing, modes, stop conditions |
| `scripts/host-check.py` | what each AI host sees when CONVERGE is invoked |
| `scripts/platform-test.py` | the Python side of portability: paths, locks, file replacement, hooks |
| `scripts/skill-update-test.py` | the updater: signatures, digests, sizes, throttle, atomicity, concurrency, every failure mode |
| `scripts/release-test.py` | the release tooling: a deterministic manifest, every way a release can be incomplete or ambiguous, signatures made and broken, and the proof that CI cannot sign |

Two rules that are not negotiable, because breaking either one is the kind of bug that eats
somebody's real state:

- **A test never touches the real `~/.converge`, `~/.claude` or `~/.codex`.** Import
  `scripts/testhome.py` before anything is launched, or set `CONVERGE_HOME` yourself. There is a
  check in `platform-test.py` that this holds.
- **A test never points at production.** No test in this repository contacts
  converge.pairwork.net.
- **A test never needs a key.** `release-test.py` makes an Ed25519 key in its own process, uses
  it, and lets it go with the scratch directory. Nothing in this repository reads the real
  release-signing key, and nothing should ever be written that could.

### Running CONVERGE in a real host

The one thing CI cannot do. [`docs/HOST-SMOKE-TEST.md`](docs/HOST-SMOKE-TEST.md) is a fifteen
minute checklist for Claude Code and Codex: installation, invocation, the banner, the reply
modes, the live display, interruption, transcripts, updates. Nobody has run it on Windows or
macOS. A completed run, pass or fail, is one of the most useful things anyone can contribute.

## Style

The code aims to read as prose with a reason attached. A comment that says *why* is worth
several that say *what*.

Two conventions you will notice, and should follow:

- **One place knows each rule.** `bridge/src/platform.hpp` is the only file with a platform
  conditional. `VERSION` is the only place the version is written. A rule spelled out in nine
  places cannot be changed; a rule in one function can be read, tested and changed.
- **No dashes as punctuation.** No em dash, no en dash, and no `--` standing in for one, in
  prose, comments, documentation or user-facing strings. Use a comma, a colon, a semicolon,
  parentheses, or a full stop and a new sentence. `--` in code is exactly what it is: an option
  prefix, an end-of-options separator, the decrement operator.

Match the surrounding code for everything else.

## Pull requests

- One change per pull request, with a description of the problem it solves.
- Say which platforms you ran the tests on. CI will run Linux, Windows and macOS.
- If it changes anything a user sees, say what they will see instead.
- If it changes the wire protocol, `agent/protocol.md` changes with it: the relay reads that
  document as the definition.

## Licence

CONVERGE client software is licensed under the GNU General Public License v3.0 or later. By
contributing you agree that your contribution is licensed under those terms. Do not paste in
code whose licence you have not checked.
