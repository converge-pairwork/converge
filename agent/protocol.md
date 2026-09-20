# Wire protocol v3

Transport: WebSocket, path `/v1/ws`, over TLS (`wss://`). A client must verify the certificate; plain `ws://` is for a local development relay and nowhere else. Where TLS is terminated on the service side is an operational matter and is not part of this protocol: the guarantees below hold whatever a client connects through, because the payloads are sealed end to end before they reach it.

The call model introduced in v2 replaces v1's pre-provisioned rooms with **calls**: every API key is an addressable
endpoint, either side may initiate, and the callee's policy decides whether the call
connects, rings for acceptance, or is refused.

v3 adds per-call key derivation and prepares referee round identities before signing.
Upgrade the relay and both bridges together. A call requires `call-keys-v3` on both
endpoints; referee mode requires `exchange-v3`. Old endpoints are refused explicitly.

## Identity

| | |
|---|---|
| **API key** (`cvg_…`) | bearer credential of one team member. **Only its SHA-256 is stored**; the plaintext is returned once at creation and can never be shown again. |
| **Identity key** | an Ed25519 keypair held by the member. Only the public half (`ssh-ed25519 AAAA…`) is registered, and the secret never leaves their machine. |
| **Handle** (`cvh_…`) | public address others dial. Safe to publish to whoever should be able to call. |
| **Alias** | human name, unique per account. Usable as a destination *within* the account only. |

A key may have several live connections (one per AI session). An incoming call rings all
idle ones; the first to accept takes it, the rest get `bye` with `reason=answered_elsewhere`.

## Text frames (control, JSON)

Client → relay

| t | fields | notes |
|---|---|---|
| `hello` | `pub` (base64 X25519, 32 B), `v`, `features` (`["call-keys-v3", "exchange-v3"]`), plus **either** `key` (bearer) **or** `handle` + `sig` (+ optional `pub_sig`) | must be the first client frame |
| `call` | `to`, a handle, or an alias within your account | |
| `accept` | `call_id` | only from a session still idle and ringing; competing invitations to that session are cancelled |
| `reject` | `call_id` | declines; the call dies when no session is left ringing |
| `hangup` | `call_id?` | only a participant may end the call |
| `ping` | | |

Relay → client

| t | fields |
|---|---|
| `challenge` | `nonce`, `v`, sent by the relay **before** `hello`; identity auth signs it |
| `welcome` | `handle`, `alias`, `account`, `balance` (prepaid, CONVERGE base units), `policy`, `auto_accept`, `auth` (`bearer`/`identity`), `identity`, `features`, `plan` (the account's limits: `id`, `members`, `concurrent_calls`), `v` |
| `calling` | `call_id`, `to`, `alias`, `auto`; your call is ringing |
| `incoming` | `call_id`, `from`, `from_alias`, `same_account`, `auto` |
| `connected` | `call_id`, `key_context_version` (3), `role` (`caller`/`callee`), `peer`, `peer_alias?`, `peer_pub`, `peer_identity`, `peer_pub_sig` |
| `bye` | `call_id`, `reason`, `hangup`, `answered_elsewhere`, `peer_disconnected` |
| `usage` | `units` (CONVERGE base units charged for this frame; `0` when it is delivered late), `balance` (prepaid, base units), after each accepted frame |
| `delivery` | `regime` (`zero_credit`), `delay_ms`, `unfunded_message_count`, `msg`; sent just before the `usage` of every frame accepted without usable balance. It is for the sending user only and is never forwarded |
| `release_held` | `exchange_id`, `round`, `delay_ms`; referee mode, to both sides: the round is complete and is released after the delay |
| `error` | `code`, `msg` |
| `pong` | |

Error codes: `bad_key`, `bad_signature`, `bad_hello`, `unknown_peer`, `peer_offline`, `call_denied`,
`busy`, `self_call`, `no_call`, `call_limit`, `metering_error`, `throttled`,
`daily_cap`, `frame_too_large`, `exchange_state`, `feature_unsupported`.

## Binary frames (payload)

Opaque ciphertext, ≤ 256 KiB, forwarded verbatim to the other end of the established
call. Billed to the **sender's** account in CONVERGE (1 CONVERGE = 1,000,000 base units) at
the relay's traffic tariff, currently 0.05 CONVERGE per MiB (50,000 base units per MiB).
The charge is computed on exact byte counts with the fractional remainder carried per
account, so it does not depend on how the bytes are split into frames. Rate limiting is separate and counts 4-byte units.

**Delivery speed.** There is one product. A frame the sender's account has balance for is
charged and forwarded at once. A frame it has no balance for (balance 0, or less than this
frame's charge) is never refused: it is not charged, and it is forwarded after
`min(n, 30)` seconds, where `n` counts the account's frames sent that way. `n` belongs to the
account, is kept across calls, connections, members, top-ups and restarts, and is never reset.
Frames of one connection are always forwarded in the order they were sent, and a `hangup`
waits for the frames before it. Each such frame is answered with a `delivery` frame carrying
the reminder for the user. Layout
produced by the bridge (the relay does not parse it):

```
[12 B nonce][ciphertext || 16 B Poly1305 tag]
```

AAD = the sender's public key as lowercase hexadecimal ASCII. Nonce = 32-bit direction
tag ‖ 64-bit counter. Both integers use big-endian encoding; the lower public key sends
with direction 0 and the higher with direction 1.

Derive 64 bytes with HKDF-SHA256: IKM is the X25519 shared secret, salt is `converge-v3`,
and info is `lower_pub_raw || higher_pub_raw || call_id_utf8`. The first 32 bytes protect
messages from the lower public key; the last 32 protect the opposite direction. Each new
call resets counters but uses a different key. Bridges reject empty or previously used
call IDs for their entire process lifetime, including reconnects.

Under referee mode, only the single reveal owed by a committed endpoint is accepted.
Other binary payloads are rejected before billing; bridges also discard uncommitted
incoming payloads. This applies to result proposals as well as ordinary messages.

## Authentication

Two ways in, per member:

**Bearer**, `hello` carries `key`. The relay hashes it and looks up the digest; it holds no
usable copy. Set `bearer_enabled: false` on a member to refuse this mode entirely.

**Identity key**, `hello` carries `handle` and `sig`, an Ed25519 signature over

```
converge-auth-v1\n<handle>\n<nonce>
```

verified against the member's registered public keys. No secret is transmitted or stored.
`pub_sig` optionally signs

```
converge-session-v1\n<handle>\n<ephemeral X25519 pub, base64>
```

which binds this session's encryption key to the long-lived identity. The relay forwards
both to the peer in `connected`, so the peer can verify the ephemeral key really came from
that identity, and pin it (trust on first use). A relay that swapped keys would have to
forge this signature.

Only Ed25519 is accepted: it is `ssh-keygen`'s default, cheap for ssh-agent to sign, and
keeps the verifier to one code path.

## Invites

An invite is a one-time bootstrap code that provisions the *other* side of a conversation.
The guest creates an Ed25519 identity locally and presents its public key when redeeming.
In one transaction, the relay creates an identity-only member on the **inviter's** account,
registers that public key, preserves a host-specific call grant, and deletes the invite row.
The guest needs no wallet or credits; the inviter pays for traffic and the new member uses
one of the inviter's member slots. The private identity never leaves the guest's machine.

Codes are stored hashed, like keys, and returned once. Host-paid codes are single-use and
disappear immediately after successful redemption; a failed redemption leaves the code
available. They carry an expiry (a week by default). Hosts can revoke outstanding codes.
The unauthenticated redeem endpoint treats the invite as the bootstrap credential and binds
it to the first successfully registered public key.

A connected bridge can mint one over the control channel with `invite_create`
(`{label, ttl_sec, max_uses, billing}` → `invite` frame with `code`, `host_handle`,
`billing`, `expires`, `max_uses`, `share`), authenticated by the member key already in use,
so an AI session can produce a shareable code without sending the user to the web
application. `billing` is `host` (default: the guest is redeemed onto the inviter's account)
or `split` (the guest brings its own account and links its existing member with `/link`;
each side pays for what it sends).

## Referee mode (opt-in barrier)

A call starts in **instant** mode: binary frames are forwarded the moment they arrive and
the relay holds nothing. Either side may propose switching the barrier on; it changes only
once the peer agrees, and either side may propose switching it off again the same way.

While on, each endpoint first sends `round_prepare` and receives `round_ready` with the
same allocated exchange ID and round number. It then signs and commits to its payload.
Every message goes through this two-phase round:

```
commit   A → H(a)        B → H(b)      relay releases both only when both are in
reveal   A → a           B → b         relay releases both only when both are in
```

Each side then checks `H(peer bytes)` against the commitment the peer was bound to. A peer
that reveals anything else is caught (`commitment_broken`), and nothing it sent is trusted.
Commitments are signed with the member's identity key when it has one, so they are
non-repudiable rather than merely checkable:

```
converge-commit-v1\n<exchange_id>\n<round>\n<hash>
```

An identity-authenticated peer must supply a valid commitment signature; the receiving
bridge verifies it before revealing its own payload. Missing or invalid signatures fail
the exchange. A bearer-authenticated peer still has hash commitments but no identity signature.
The relay reads none of the payload; it holds opaque blobs. On timeout it
discards both halves (releasing the one that arrived would reward whoever stalled), tells
both sides `round_expired`, and clears the buffer; **the mode itself stays on**.

Client → relay

| t | fields |
|---|---|
| `referee_propose` | `on` (bool), `timeout_sec`, per-round deadline once on |
| `referee_accept` / `referee_decline` | |
| `round_prepare` | allocate or join the current round |
| `commit` | `exchange_id`, `round`, `hash`, `sig?`, context must match the prepared round |

Relay → client

| t | fields |
|---|---|
| `referee_offer` | `on`, `timeout_sec`, `from` |
| `referee_pending` | your proposal is waiting on the peer |
| `referee_mode` | `on`, `timeout_sec`, now in force for both |
| `referee_declined` | `on`, the proposed change was refused |
| `round_ready` | `exchange_id`, `round`, `deadline`, context to sign |
| `commit_held` / `reveal_held` | the barrier is holding yours |
| `commits` | `mine`, `peer`, `peer_sig`, `receipt` |
| `round_release` | `receipt`, followed by the peer's binary frame |
| `round_expired` | `round`, `reason` |

Both sides proposing the same change at once counts as agreement, not a conflict.

### Result proposals

`converge_propose_result` requires `result` text or a `sha256:` digest followed by 64
lowercase hex digits. An intentionally empty result must be passed explicitly as
`result: ""`. If both fields are provided they must agree. Summaries alone never count
as results. Under referee mode this tool participates in the same barrier as
`converge_send`, requires a positive `wait_sec`, and returns verification details in
`exchange`. Both endpoints must submit for the round to complete.

### Round receipts

`commits` and `round_release` carry a receipt the relay signs with its own Ed25519 key:

```
converge-receipt-v1\n<call_id>\n<exchange_id>\n<phase>\n<round>\n<commit_a>\n<commit_b>\n<ts>
```

`GET /v1/relay-key` publishes the public half, so either party, or a third party later,
can verify what was committed and when without learning anything about the content. The
relay is a notary, not a judge: it attests to commitments and timing, and never to meaning.

## Accept policies

Set per key; decides who may reach it. `auto_accept` then decides whether an allowed call
connects immediately or has to be accepted by the session that takes it.

| policy | who may call |
|---|---|
| `none` | nobody, outgoing calls only |
| `account` | keys on the same account |
| `allowlist` | same account, plus handles explicitly allowed for that key |
| `any` | anyone who knows the handle |

## REST, all JSON

People sign in and manage their account in the web application at `/`, which speaks QSF
over `POST /rpc`. The routes below are JSON for agents and scripts. A session (`Bearer`) is
obtained only with a Solana wallet signature, through the same challenge the web
application uses: request a challenge, sign its `message` (UTF-8 bytes) with the wallet's
Ed25519 key, and send the base58 signature back. No route sells balance or changes an
account's limits: prepaid CONVERGE is added only by a verified transfer to the Converge
Treasury (`/v1/solana/topup`).

| method | path | auth | body / query | result |
|---|---|---|---|---|
| GET | `/v1/solana/auth/challenge?wallet=<base58>` | - | | `{wallet, nonce, message, expires_at}`, single use, 5 minutes |
| POST | `/v1/solana/auth/verify` | - | `{wallet, nonce, signature}` (base58) | `{session, wallet, account, network}` |
| GET | `/v1/relay-key` | - | | `{pubkey, receipt_message}`, for verifying round receipts |
| GET | `/v1/invite/{code}` | - | | `{host_handle, host_alias, label, billing, pays, expires, uses_left, relay, setup_guide}` |
| POST | `/v1/invite/{code}/redeem` | - | `{alias, pubkey}` | `{handle, alias, auth:"identity", relay, note}`, host-paid invitations: registers the public key and consumes the invite |
| POST | `/v1/invite/{code}/link` | - | `{handle}` | `{host_handle, billing, note}`, split invitations: lets your existing member and the host call each other |
| GET | `/v1/account` | Bearer | | `{address, balance, delivery{regime, unfunded_message_count, next_delay_sec}, plan{…}, keys:[…], invites:[…]}` |
| POST | `/v1/keys` | Bearer | `{alias, policy, auto_accept, rate_per_sec, burst, daily_cap}` | `201 {key, key_prefix, handle, alias, policy, auto_accept, note}`, **the only time `key` is ever returned** |
| DELETE | `/v1/keys/{handle}` | Bearer | | `{ok}` |
| POST | `/v1/keys/{handle}/policy` | Bearer | `{policy, auto_accept, bearer_enabled}` | `{ok}` |
| POST | `/v1/keys/{handle}/identity` | Bearer | `{pubkey, label}` | `{ok, pubkey, label}` |
| POST | `/v1/keys/{handle}/identity/remove` | Bearer | `{pubkey}` | `{ok}` |
| POST | `/v1/keys/{handle}/allow` | Bearer | `{handle}` | `{ok}` |
| DELETE | `/v1/keys/{handle}/allow/{peer}` | Bearer | | `{ok}` |
| POST | `/v1/keys/{handle}/invite` | Bearer | `{label, ttl_sec, max_uses, billing}` | `201 {code, host_handle, billing, expires, max_uses, share, note}` |
| DELETE | `/v1/invites/{code_prefix}` | Bearer | | `{ok}` |
| GET | `/v1/usage?since=unix` | Bearer | | `{rows:[{ts, key_prefix, alias, peer, units, bytes_out, bytes_in}]}`, `units` = base units charged |
| GET | `/v1/solana/access` | Bearer | | `{balance_base_units?, account_balance_base_units, delivery (funded/zero_credit), unfunded_message_count, next_delay_sec}`, wallet balance, prepaid balance and delivery speed of the signed-in account; `503` (without `balance_base_units`) while the wallet balance cannot be read |
| POST | `/v1/solana/topup` | Bearer | `{transaction_signature}` | `{status, received_base_units?, balance}`, credits what the Treasury verifiably received from this wallet; `202` while pending |
| GET | `/healthz` | - | | `ok` |

Members are addressed in URLs by their **public handle**, a secret never appears in a path.
`GET /v1/account` lists each member's `key_prefix` (never the secret) and `identity_keys`.
On a member, `rate_per_sec` and `burst` count 4-byte rate-limit units; `daily_cap` counts
base units charged in the last 24 hours (default 5,000,000, i.e. 5 CONVERGE).

**Account limits.** `GET /v1/account` reports them in a `plan` block: `{id, name, members,
concurrent_calls, monthly_units, members_used, calls_active, since, until, renews}`. The
name is historical; there are no plans to choose, and `monthly_units`, `since`, `until`
and `renews` describe the former plans. Every new account has the default limits (2
members, 1 concurrent call). `POST /v1/keys`, and redeeming a host-paid invitation, fail
`409` at the member limit; a `call` is refused with `call_limit` when either side's account
is already at its `concurrent_calls`. `0` means unlimited.

## Invited guest acceptance

Redeeming a host-paid invitation records a guest-to-host acceptance grant. Allowed calls
from that guest to that host connect automatically even when the host normally prompts.
Normal reachability checks still apply; other peers do not gain automatic acceptance.
The grant ends with invitation expiry or revocation. Existing redeemed guests without
a recorded grant and split invitations retain normal acceptance behavior. This does not
wake an idle AI turn: the bridge connects and buffers messages until the assistant resumes.

## Local outcome reporting

The local MCP bridge also provides `converge_connections`, `converge_set_connection_label`,
and `converge_sessions`. These maintain the user's connection labels and up to 200 past
sessions in `~/.converge/connections.json` (or beside the configured peer-pin file). This
file stays on the user's machine. `converge_call` accepts a saved label and an optional
`topic`; a call always starts a new session. Session topics and results are recorded locally.

The MCP bridge returns a call ID and locally submitted canonical text with result
confirmations. `converge_status`, `converge_receive`, and `converge_hangup` expose
`completed_calls`: the last ten completed calls with their peer, end time, and round
outcomes. Active `rounds` belong only to the current call. Each matched round records
the two digests and the local canonical text, or null when only a digest was submitted.
This history is held only in bridge memory and clears when the bridge restarts; it is
not sent to or stored on the relay. A match attests accepted text for that call/round,
not human approval or completion under a subsequent changed brief.

## In-session interaction (local only)

`converge_session` is a tool of the local bridge and adds nothing to the wire: its `reply` sends
the same sealed `{kind, body, round, seq, ts}` envelope as `converge_send`, and its `wait` reads
the same inbox as `converge_receive`. The interaction state, the user's guidance, the delivery
notice and the transcript it shows stay in the bridge process and are never sent to the relay
or the peer. A peer that does not use it is indistinguishable from one that does.
