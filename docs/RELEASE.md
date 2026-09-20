# Making a CONVERGE release

How a release is built, signed and published, and what a person who downloads one can actually
check. It is written for the project owner, who does the signing, but the parts about what is
established and what is not are for anyone.

The short version: **CI builds and drafts. The owner signs. Only then is anything published.**
The release-signing key is never in this repository, never in GitHub Actions, never in a
repository secret, and never on a machine that serves releases.

---

## 1. The trust model

A release makes two separate claims, and it is worth refusing to blur them.

**Integrity — are these the bytes that were published?** `manifest.json` names every artifact
with its SHA-256 and its byte size, and `SHA256SUMS` covers the release as a whole. The
installer and the updater check both before anything replaces anything. This makes a corrupted
or truncated download loud.

Integrity alone is weaker than it looks. A checksum served from the same release as the binary
it describes is not an independent statement: whoever could replace one could replace the other.

**Authenticity — is this the release CONVERGE published?** `manifest.json.sig` is a detached
Ed25519 signature over the exact bytes of `manifest.json`, made by the project owner on a
machine that is not the one serving releases, under a key that has never been uploaded
anywhere. An installed client checks it against a public key compiled into the client itself,
so it is checking against a key it already had rather than one fetched alongside the thing the
key is meant to vouch for.

That is the whole reason CI does not sign. If the signing key were a GitHub secret, then a
compromise of the repository, of the Actions runner, or of any action the workflow calls would
be a compromise of the signature too, and the signature would be adding ceremony rather than
security. Held offline, it means that even someone who fully controls this repository and its
release assets cannot produce an update that an installed CONVERGE accepts.

### What each layer actually protects against

| | Caught by | Not caught by |
|---|---|---|
| Corrupted or truncated download | digest, size | — |
| Tampering by a network attacker | TLS, digest, size | — |
| A substituted release asset, signing key intact | manifest signature | digests alone |
| A compromised GitHub account or CI, signing key intact | manifest signature, for everyone already installed | digests alone |
| A compromised signing key | nothing here; rotation and revocation | everything |

---

## 2. Bootstrap: what a first install establishes

This is the part that is easy to overstate, so it is stated plainly.

A CONVERGE client verifies future releases with a public key compiled into it. The first
install has no such client yet. Everything it uses — the installer, the manifest, the binary
and the embedded public key — arrives over the network at the same moment. **No signature can
make a first install self-verifying**, because the verifier and the key arrive alongside the
thing they are checking. Anyone who says otherwise has moved the problem, not solved it.

So what a first install rests on is:

1. **TLS to a named host.** `https://converge.pairwork.net` for the installer,
   `https://github.com/converge-pairwork/converge` for the release. Certificate verification is
   never relaxed anywhere in the client, and a redirect off HTTPS, or onto a host that is not
   in a fixed list compiled into the code, is an error rather than a download.
2. **Two origins rather than one.** The documented install path fetches `install.sh` from
   converge.pairwork.net and the release from github.com. `install.sh` carries the release
   public key, so once a key is pinned, a compromise of the GitHub release assets alone is
   caught at install time by a key that came from somewhere else. It takes both to go wrong.
3. **A fingerprint a person can cross-check.** The key's fingerprint is published in more than
   one place that an attacker would have to compromise separately (see below). A careful user
   compares them before installing. Most users will not, and the model does not pretend they do.
4. **Source they can read.** The client is GPLv3 and the release carries `converge-src.tar.gz`.
   A user who trusts nothing above can build the bridge from that source and check the binary
   the release publishes against their own build.

After the first install, the picture changes completely: the pinned key governs every update,
and it does so from a file already on the user's disk. This is the smallest credible model for
a project this size, and it is the one CONVERGE claims — not "verified from first byte", but
"trusted once, at a moment the user chooses, and verified from then on".

### The canonical key, and where it is cross-checked

There is exactly **one** canonical release key. It is canonical in
`agent/converge-update.py` (`RELEASE_KEYS`), in the public repository's Git history, where the
commit that introduces it is visible to everyone for ever.

Its fingerprint is republished, unchanged, in:

- `SECURITY.md` in this repository
- `agent/install.sh` (`RELEASE_KEY`, the key itself)
- the release notes of every signed release
- https://converge.pairwork.net

Those are cross-checks, not alternative authorities. If they ever disagree, the one in the Git
history of the public repository is the key, and the disagreement is a security report.

---

## 3. Generating the production key

**Not done by CI, not done by an assistant, and not done twice.** The owner does this once, on
a machine that does not serve releases, ideally offline:

```sh
openssl genpkey -algorithm ed25519 -out converge-release.pem
chmod 600 converge-release.pem
```

Then take the public half and its fingerprint:

```sh
python3 scripts/sign-manifest.py --key converge-release.pem --public-key
```

which prints:

```
public key (RELEASE_KEYS entry): <44 characters of base64>
fingerprint:                     SHA256:xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx xxxxxxxx
```

The private key is then backed up the way an irreplaceable secret is backed up — offline, in
more than one place, in a form that survives the loss of the machine it was made on — and never
copied to a server, a CI system, a password manager that syncs through a third party, or any
machine that publishes releases.

> **Losing it** means every installed client stops accepting updates until its user installs a
> new client by hand. **Leaking it** means an attacker can sign a release that every installed
> client accepts. The second is worse.

### Representation, exactly

| | Form |
|---|---|
| Private key | Ed25519, PEM PKCS#8 (a `BEGIN PRIVATE KEY` header), on the owner's machine only |
| `RELEASE_KEYS` entry | base64 of the **raw 32-byte** public key: 44 characters, ending `=`. Not PEM, not DER, no armour, no comment. |
| `install.sh` `RELEASE_KEY` | the same 44 characters |
| Fingerprint | `SHA256:` then the SHA-256 of those raw 32 bytes, hex, in eight groups of eight |
| Signature file | base64 of the raw 64-byte Ed25519 signature, one line, one trailing newline |

---

## 4. Installing the public key

Once the key exists, and not before:

1. Put the 44-character base64 in `agent/converge-update.py`:

   ```python
   RELEASE_KEYS = ('<base64>',)
   ```

2. Put the same 44 characters in `agent/install.sh`:

   ```sh
   RELEASE_KEY="${CONVERGE_RELEASE_KEY-<base64>}"
   ```

3. Put the fingerprint in `SECURITY.md`, replacing the note that says there is not one yet.
4. `make check`. `scripts/release-test.py` refuses a tree where those two files pin different
   keys, or where a pinned key is not a real 32-byte key, so a placeholder or a typo fails here
   rather than in the field.
5. Commit, on its own, with a message that says what the key is. That commit is the public
   record of when CONVERGE began requiring signatures.

**Never put a stand-in there.** An entry that is not a key makes every install and every update
fail closed for no reason; an entry that is a key is a key somebody could hold. Until the real
key exists, both are empty, and everything that reports on authenticity says so rather than
passing: `signed_by_converge` returns `None` and never `True`, and
`scripts/release-verify.py` exits non-zero with *"RELEASE_KEYS is empty: authenticity cannot be
established"*.

---

## 5. Cutting a release

### What CI does

`.github/workflows/release.yml`, on a `v*.*.*` tag:

| Stage | What must hold |
|---|---|
| **safety** | `safety-check.py`, `version-check.py`, `release-test.py`, and the tag equals `VERSION` |
| **bridge** × 4 | Linux x86_64, Windows x86_64, macOS arm64, macOS x86_64: configure, build, `ctest`, host check, platform tests, updater tests, and the staged binary carries the version. `fail-fast: true` — one platform failing fails the release |
| **package** | assemble `dist/`, `release-manifest.py --complete --tag --commit`, `sha256sum -c SHA256SUMS` |
| **draft** | a **draft** GitHub release with every artifact attached |

`--complete` is what makes a silently incomplete release impossible: it refuses a directory
missing any of the four binaries, carrying a file the release does not publish, carrying a
bridge under a name that is not the canonical one, or mapping one file to two platforms.

Nothing in that workflow reads a repository secret, and nothing in it signs. The draft is not
published by anything automatic; it becomes public when a person publishes it.

### What the owner does

```sh
# 1. fetch the draft's manifest
gh release download v0.1.1 --pattern 'manifest.json' --dir ~/release/v0.1.1
cd ~/release/v0.1.1

# 2. read it. does it say what this tag and this commit should say?
cat manifest.json
#    - "tag": "v0.1.1" and "version": "0.1.1"
#    - "commit": the commit the tag points at, which `git rev-parse v0.1.1^{}` prints
#      (true of every tag but v0.1.1, whose history was rewritten after release: section 10)
#    - four entries under "bridge", each with the canonical name, os, arch, format, size, sha256
#    - the run that produced it, linked from the draft's notes, built from that same commit

# 3. sign those exact bytes, offline, with the key
python3 sign-manifest.py --key ~/keys/converge-release.pem \
    --manifest manifest.json --out manifest.json.sig

# 4. check it the way an installed client will
python3 scripts/release-verify.py --manifest manifest.json --signature manifest.json.sig
#    (from a checkout; with the key pinned this uses the client's own verifier and its own key)

# 5. upload the signature to the draft
gh release upload v0.1.1 manifest.json.sig

# 6. publish, by hand, when and only when the above is all true
gh release edit v0.1.1 --draft=false
```

`scripts/sign-manifest.py` is a single file with no dependency on this source tree: copy it to
the machine that holds the key. It takes an explicit key path and an explicit manifest path,
reads nothing from the environment, searches for nothing, never writes or prints key material,
never modifies the manifest, refuses to sign anything that is not a canonically serialised
CONVERGE release manifest, and will not overwrite an existing signature without `--force`.

It needs an `openssl` that supports Ed25519 `-rawin`, which means OpenSSL 3. macOS ships
LibreSSL under the name `openssl`; use `brew install openssl@3` and pass `--openssl`.

### The one thing that cannot be automated

Step 2. The signature says "the owner looked at this manifest and vouched for it". If that step
is skipped, the signature means only that the key was applied to whatever CI produced, which is
a claim CI could have made on its own.

---

## 6. What a release contains

| Artifact | |
|---|---|
| `converge-bridge-<version>-linux-x86_64` | the bridge, ELF |
| `converge-bridge-<version>-windows-x86_64.exe` | the bridge, PE |
| `converge-bridge-<version>-macos-arm64` | the bridge, Mach-O |
| `converge-bridge-<version>-macos-x86_64` | the bridge, Mach-O |
| `skill.md` | the canonical skill, stating the same version |
| `converge-live.py` | the live rendering hook |
| `converge-update.py` | the updater, so a new installation gets the current one |
| `install.sh` | the installer |
| `converge-src.tar.gz` | the source the release was built from |
| `manifest.json` | what everything above is, and what it hashes to |
| `SHA256SUMS` | the same digests, in the format `sha256sum -c` reads |
| `manifest.json.sig` | the owner's detached signature, uploaded after the draft is built |

### The manifest

Schema 2. Sorted keys, two-space indent, one trailing newline, and nothing in it that depends
on when or where it was built, because the signature is over these exact bytes and a manifest
that re-serialises differently is a manifest whose signature cannot be checked.

```json
{
  "schema": 2,
  "product": "converge",
  "component": "client",
  "version": "0.1.1",
  "tag": "v0.1.1",
  "commit": "<40 hex characters>",
  "repository": "converge-pairwork/converge",
  "license": "GPL-3.0-or-later",
  "files": {
    "skill":    { "path": "skill.md",         "sha256": "<64 hex>", "size": 15754 },
    "renderer": { "path": "converge-live.py", "sha256": "<64 hex>", "size": 4562 }
  },
  "bridge": {
    "linux-x86_64": {
      "path": "converge-bridge-0.1.1-linux-x86_64",
      "sha256": "<64 hex>", "size": 5122096,
      "os": "linux", "arch": "x86_64", "format": "elf"
    }
  },
  "extra": {
    "converge-update.py":   { "path": "converge-update.py",   "sha256": "<64 hex>", "size": 32202 },
    "install.sh":           { "path": "install.sh",           "sha256": "<64 hex>", "size": 13418 },
    "converge-src.tar.gz":  { "path": "converge-src.tar.gz",  "sha256": "<64 hex>", "size": 163750 }
  }
}
```

Every `path` is a name **relative to the release**, never a URL. An updater that took its
origin out of a manifest would be an updater that a compromised manifest could point anywhere;
the release source is the one the installation was set up with, and nothing in this file can
move it.

Each platform key is `<os>-<arch>`, and the entry repeats `os` and `arch` in its own fields. A
client checks that the filing and the contents agree: an entry under `linux-x86_64` claiming
`os: windows` is refused rather than reconciled. Two platforms naming the same file is refused
as an ambiguous mapping, and a manifest that names any key twice is refused before it is read.

---

## 7. Verification sequences

**A first install** (`agent/install.sh`), in order, stopping at the first failure:

1. fetch `manifest.json` from the release over HTTPS
2. where `RELEASE_KEY` is pinned: fetch `manifest.json.sig` and verify it over the manifest
   bytes as served, with that key; a missing manifest, a missing signature, a signature that
   does not verify, or no `python3` to verify with, each stop the install
3. read the manifest: refuse a foreign product, an unknown schema, a duplicate key, an
   ambiguous platform mapping
4. select the entry for this operating system and architecture, and no other
5. download that artifact
6. check its byte size against the manifest
7. check its SHA-256 against the manifest
8. install it atomically into `~/.local/bin`, through a temporary file and a rename
9. run it once, to establish that what was installed runs at all

Where the release has no binary for this machine, the source tarball is fetched and checked
against the manifest — against the signed manifest, where a key is pinned — and the bridge is
built locally. With a key pinned there is no unsigned fallback at any step.

**An update** (`agent/converge-update.py`), in order:

1. take the update lock, or leave; unless forced, stop if the last check was under an hour ago
2. fetch `manifest.json` from the release source recorded in `setup.json`
3. where `RELEASE_KEYS` is pinned: fetch `manifest.json.sig` and verify it over the bytes as
   served, **before the manifest is parsed and before one value out of it is looked at**
4. refuse a schema newer than the updater understands, or a manifest that names anything twice
5. compare versions numerically; never the same version again, never backwards, and never a new
   major version automatically — that is announced and held
6. for each of skill, renderer and bridge: take the path and digest from the manifest, refuse
   anything that is not a plain path under the release, fetch it, check the size, check the
   SHA-256, check it is the kind of file that belongs at that target
7. stage everything in a scratch directory; only when all of it is present and verified is
   anything on disk touched
8. replace each target atomically, with the Windows running-binary path where it applies
9. record the outcome in `update.json`

**Failure behaviour, in both:** fail closed, and leave the working installation exactly as it
was. A missing or bad signature, an unknown key, a malformed manifest, the wrong OS, the wrong
architecture, a duplicate mapping, a digest mismatch, a size mismatch, an unexpected redirect,
a host outside the allowlist, a redirect off HTTPS, an unsupported schema, or an interruption
part way through, all leave the installation untouched. A partially completed install is
retried at the next check; on Windows, a replacement that cannot complete puts the old binary
back. An update that cannot happen is never a CONVERGE failure: CONVERGE does not wait for the
updater and does not fail because of it.

---

## 8. Rotating or revoking the key

`RELEASE_KEYS` is a tuple, newest first, because rotation has to be possible without stranding
installations that have not updated yet.

- **Rotation.** Generate the new key. Add it to the front of `RELEASE_KEYS` and leave the old
  one behind it. Release that client, signed with the **old** key, so installations that have
  only the old key can still accept it. Once that release has propagated, sign with the new key.
  Drop the old key in a later release.
- **Revocation after a compromise.** The old key cannot be un-trusted on machines that already
  have it, which is what makes a leak worse than a loss. Say so publicly, immediately, on every
  channel in `README.md`; publish the new key and its fingerprint; and expect every user to
  install by hand. There is no mechanism here that makes this painless, and pretending
  otherwise would be the wrong kind of comfort.

---

## 9. Checking a release by hand

Anyone can, with nothing but the release and this page:

```sh
gh release download v0.1.1 --dir converge-0.1.1 && cd converge-0.1.1

sha256sum -c SHA256SUMS                    # every artifact against the release's own list

# the signature, against the published key
openssl pkeyutl -verify -pubin -inkey converge-release.pub -rawin \
    -in manifest.json -sigfile manifest.json.sig

# or against the key the client itself pins, with the client's own verifier
python3 scripts/release-verify.py --manifest manifest.json \
    --signature manifest.json.sig --dist .
```

To turn the base64 in `RELEASE_KEYS` into the `converge-release.pub` that openssl wants:

```sh
{ printf '302a300506032b6570032100' | xxd -r -p; printf '%s' '<base64>' | base64 -d; } \
    | openssl pkey -pubin -inform DER -out converge-release.pub
```

And to check the fingerprint matches what is published:

```sh
printf '%s' '<base64>' | base64 -d | sha256sum
```

---

## 10. The commit `v0.1.1`'s manifest names

`v0.1.1` was published, and then its history was rewritten once, on the owner's instruction, to
remove `Co-Authored-By` trailers from four commit messages. The tag was moved to the rewritten
commit. Nothing else about the release changed: no artifact was rebuilt, no asset was
re-uploaded, `manifest.json` was not touched and was not re-signed.

So the signed manifest names a commit that is no longer reachable:

| `manifest.json` says | the repository now has | |
|---|---|---|
| `b03448ac9f7c85e951e5cf3c70217949e6e91234` | `b3cdac16b653c36df1ed687bc21f82653fe80c89` | what `v0.1.1` points at |
| `816bfe4eaa323f669163db0b33265bd6b08396c3` | `fd1644ac374f45e37aba336c1774addcbffe1ba6` | |
| `dd03dd7509a16b8b9aab530223160b8d105ced3f` | `3a475b3538b611b967f964f56c2a1fcc8e0d247c` | |
| `723d2db4f76a9ffbe275c2e97235e75dd1986e38` | `fe74ac2be09bfd9c26366ae65ddcbb26c45c830a` | |

Only commit messages differ across that mapping. Every tree is byte for byte what it was, which
is why `converge-src.tar.gz` still hashes to what the manifest says it does.

What this does and does not affect:

- **The signature still verifies.** It is over the bytes of `manifest.json`, and those bytes are
  unchanged. Section 1 is unaffected.
- **Every artifact still verifies.** Sizes and SHA-256 digests are over uploaded bytes, and no
  asset was replaced.
- **The check in section 5 no longer holds for this tag.** `git rev-parse v0.1.1^{}` prints
  `b3cdac16`, while the manifest says `b03448ac`. For `v0.1.1`, and only for `v0.1.1`, that
  mismatch is expected and this table is the reason. For every later tag the two must agree,
  and a mismatch means something is wrong.

Nothing in the install or update path reads the manifest's `commit` field, so no client noticed
and none will. It is a record for people, and the record would be broken without this table.
