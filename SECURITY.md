# Security

## Reporting a vulnerability

Write to **converge-pairwork@mm-studios.com**.

Please do not open a public issue for anything that looks like a vulnerability. A public issue
is a disclosure, and it happens before anyone can fix it.

Tell us what you found, how to reproduce it, and what you think an attacker gets out of it. You
will get an acknowledgement, and we will tell you what we find and when it is fixed. If you want
credit in the release notes, say so; if you would rather not be named, say that instead.

CONVERGE is a small project. There is no bug bounty.

### What must never go into a report

A vulnerability report is a public-ish document that passes through mail servers and issue
trackers. Never include:

- your CONVERGE identity private key, or any part of the `identity` file
- a `cvg_` bearer key, or any other credential
- a wallet private key, seed phrase or recovery phrase
- the contents of a real negotiation, yours or anyone else's
- another person's handle, account details or transcript

None of these are needed to describe a bug. If a report genuinely cannot be made without
sensitive material, say so in the first mail and we will arrange something.

If you believe a key of yours has been exposed, remove its public half from your member at
converge.pairwork.net. That revokes it immediately, whatever else is going on.

## Local state and what protects it

The client keeps its state in one directory per user:

| Platform | Directory |
|---|---|
| Linux, macOS | `~/.converge` |
| Windows | `%LOCALAPPDATA%\CONVERGE` |

Overridden everywhere by `CONVERGE_HOME`, which is also how the tests keep away from your real
state.

It holds the things that matter: your Ed25519 identity private key, the peer identities you
have pinned, your saved connections, and the updater's record.

- On Linux and macOS the directory is `0700` and the sensitive files inside it are `0600`.
- On Windows it is `%LOCALAPPDATA%`, which is per user and not roaming, and CONVERGE additionally
  gives the directory and its sensitive files a **protected** discretionary ACL with exactly one
  entry, for the current user. Protected is the part that matters: it means nothing is inherited
  from a parent directory, so an ACL that would have been wider than `0700` does not apply. This
  is `bridge/src/platform.hpp` (`restrict_to_owner`), and `bridge/tests/test_platform.cpp` reads
  back the ACL that is actually on the object rather than trusting that the call was made. That
  test runs on a native Windows runner in CI, on every push, and passes: this is checked rather
  than asserted.

Your identity private key is generated locally and is never transmitted. Relay authentication
signs a challenge with it, so the relay stores only the public half. If you would rather the key
never sat in a file at all, `--ssh-agent` lets the bridge use a key your agent holds, including
a hardware-backed one.

## What CONVERGE protects, and what it does not

Stated as what the code establishes, not as what would sound best.

**On the bridge route**, which is the recommended one and the one in this repository:

- Every message of a call is sealed with ChaCha20-Poly1305 under a key derived from ephemeral
  X25519 keys and bound to the call. The relay routes ciphertext and counts bytes.
- The peer's long-term identity key signs its ephemeral key, so the relay cannot quietly put
  itself in the middle by substituting one. The bridge pins the peer's identity the first time
  it sees it and tells you if it ever changes.
- `converge_peer_fingerprint` gives you a short authentication string. Comparing it with the
  other person out of band is what turns "the relay says this is them" into "this is them".

**On the SSH gateway route**, which exists for people who cannot install anything: the server
does the encrypting and can read the content. This is said on every surface that offers it, and
it is the reason the bridge is recommended for anything confidential.

**Not protected, by design and by admission:**

- **Metadata.** The relay sees which handle called which, and when. A routed, metered network
  cannot not know that.
- **Traffic analysis.** Sizes and timing are visible to the relay.
- **What the AIs do with the content.** CONVERGE carries a negotiation; it does not supervise
  it. Remote content is treated as untrusted data by the skill and the bridge, never as
  instructions, but the judgement about an offer is yours.

## Releases and how to verify one

A binary and a checksum published side by side are not two independent statements: whoever could
replace one could replace the other. So a CONVERGE release is verifiable at two different levels,
and it is worth knowing which is which.

**Integrity.** Every release carries a `manifest.json` naming each artifact and its SHA-256, and
a `SHA256SUMS` over everything. The installer and the updater check the digest of every file
before it replaces anything, check that the bytes are the kind of file they claim to be (an ELF
where an ELF belongs, a PE where a PE belongs), and fail closed on any mismatch. This is what
makes a release reproducible and a corruption loud.

**Authenticity.** The manifest is signed, detached, with an Ed25519 key held by the project
owner. That key is not in this repository, not in GitHub Actions, not in a repository secret and
not on any machine that serves releases: CI builds a release and drafts it, and the owner signs
the manifest offline before anything is published. The public half is compiled into the client
(`RELEASE_KEYS` in `agent/converge-update.py`) and carried by the installer (`RELEASE_KEY` in
`agent/install.sh`), so an installation checks a signature against a key it already had rather
than one fetched alongside the thing the key is meant to vouch for.

This is what makes a compromise of the repository, of CI, or of the release assets insufficient
to update an installed CONVERGE. It is also the reason CI does not sign: a signing key held by
the same system that builds the artifacts adds ceremony, not security.

### The CONVERGE release signing key

This is the **public** half of the production CONVERGE release-signing key. It is what verifies
that a release manifest was signed by the project, and it is the only key a CONVERGE client
accepts.

> **Fingerprint**
>
> ```
> SHA256:cdd8d54f 0c027837 f387bcfa 0536c738 2b49acd7 43966ad9 7d98dbaa 99555ae8
> ```
>
> **Public key** (base64 of the raw 32-byte Ed25519 key)
>
> ```
> 6STokPtBRPz4vlJ8C/n1yb8MD47bXYQz+x7mhUJLxTs=
> ```

Signature verification is **on**. A release manifest that carries no signature, or one that does
not verify against this key, is refused by the installer and by the updater, and nothing is
installed. That was not true before the commit that pinned this key, and the commit is the
public record of when it became true.

The same fingerprint is published in `agent/install.sh`, in `agent/converge-update.py`, in the
release notes of every signed release, and at converge.pairwork.net. Those are cross-checks, not
alternative authorities: if they ever disagree, the key in this repository's Git history is the
key, and the disagreement is a security report. Check it yourself with:

```sh
printf '%s' '6STokPtBRPz4vlJ8C/n1yb8MD47bXYQz+x7mhUJLxTs=' | base64 -d | sha256sum
```

The private half is held by the project owner and is not in this repository, not in GitHub
Actions, not in a repository secret, and not on any machine that serves releases.

**Bootstrap, said plainly.** A first install cannot verify itself. The installer, the manifest,
the binary and the embedded public key all arrive over the network at the same moment, so no
signature makes that moment self-verifying. What a first install rests on is TLS to a named
host, two separate origins (the installer from converge.pairwork.net, the release from GitHub)
so that one compromise is not enough, a fingerprint published in several places for anyone who
wants to cross-check, and GPLv3 source in the release for anyone who would rather build it
themselves. After that first install the pinned key governs every update, from a file already on
your disk. [`docs/RELEASE.md`](docs/RELEASE.md) sets out the whole model, including what it does
not protect against.

To check a release by hand:

```sh
sha256sum -c SHA256SUMS                    # every artifact against the release's own list
openssl pkeyutl -verify -pubin -inkey converge-release.pub -rawin \
    -in manifest.json -sigfile manifest.json.sig     # once a key is published
```

The updater will only ever follow a redirect to a host in a fixed list compiled into it, will
not leave HTTPS, and takes no URL from a manifest: a manifest names files, never where to get
them from. It refuses a manifest written to a schema it does not understand, one that names
anything twice, one that maps two platforms to the same file, and one whose entry for your
machine says it was built for another. Every failure leaves the working installation exactly as
it was.

## What the updater sends

Nothing about you. It reads four things out of your local setup, and none of them says anything
about your account: where this installation takes its releases from, and where its three
updatable files live. No handle, no key, no topic, no transcript and no identity ever reaches
the release source, and no value out of a manifest is executed, expanded by a shell, or used as
an origin of its own. `scripts/skill-update-test.py` asserts this against the shipped file.

## Scope

This repository is the CONVERGE **client**, published under the GNU General Public License v3.0
or later. Everything above describes that software. The relay, the account and billing services
and the deployment infrastructure are separate, are not published here, and are not covered by
that licence. A vulnerability in any of them still goes to the same address.
