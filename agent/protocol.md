# Wire protocol v4

The link between a CONVERGE client and the relay is **protocol v4**: one encrypted,
authenticated stream of binary QSF frames that does not depend on TLS, an Ed25519 identity that
is a Solana address, a key that is its own account until a certificate or an invitation says
otherwise, and sessions that survive the socket. It is specified in
[proto/README.md](../proto/README.md) and defined by the headers beside it: `qsf.hpp` (the
frame format), `link.hpp` (every message), `handshake.hpp` (the handshake and the sealed
stream), `certificate.hpp` (member certificates). The bridge, the relay and the web application
compile the same headers, so every end of the link speaks from one definition. This document is
the reference for an agent: what the link establishes, how invitations, calls and referee mode
behave, and what the local bridge adds on top.

Nothing else is spoken. The relay answers no JSON protocol and no earlier version of this one.

## Transport

One WebSocket, `wss://<relay>/link` (`ws://` only to a local development relay), one link
frame per binary message. A client verifies the certificate; TLS protects the connection, but
it is not what keeps anything private: every frame after the handshake is sealed with
ChaCha20-Poly1305 under keys the relay and the client derived together, and a peer payload is
sealed again, end to end, by the two bridges. Whatever carries the stream sees ciphertext.

The handshake, in four frames: `client_hello` (protocol 4, an ephemeral X25519 key, a nonce,
features), `relay_hello` (the relay's ephemeral key in the clear, its static key sealed, a
confirmation tag only the holder of the static key can compute), `client_auth` (the first
sealed frame), then `welcome` or `link_error`. Keys come from HKDF-SHA256 with the salt
`converge-v4`; the exact schedule is in the specification. The client checks the relay's static
key against the one it pinned on first use, or against `/.well-known/converge`.

## Identity

| | |
|---|---|
| **Identity key** | an Ed25519 keypair held by the member: 32 raw bytes on the wire, base58 in text, which is a Solana address. The bridge generates one on first run (`identity` in CONVERGE's state directory) and never sends the private half anywhere; `--print-identity` prints the public half as an `ssh-ed25519` line, the address and the handle. |
| **Handle** (`cvh_…`) | the public name others dial: `cvh_` plus the first 12 hex digits of SHA-256(public key). Derived, never assigned; safe to publish to whoever should be able to call. |
| **Alias** | a human name, unique per account. Usable as a destination *within* the account only. |
| **Account** | a Solana wallet's, or the key's own. A key that connects with no certificate is its own account: id from its address, balance 0, account scope. Nothing is registered first. |

`client_auth` carries the identity, its signature over

```
converge-v4-auth\n<domain>\n<identity base58>\n<h hex>\n<relay static key base58>
```

(`h` is the handshake transcript hash, so a signature obtained by one relay is worthless at
another), and a per process X25519 call key with its signature over

```
converge-session-v4\n<identity base58>\n<call key base58>
```

which the relay forwards in `connected`, so a peer can verify the call key came from that
identity and pin it. There is no bearer credential of any kind: the relay holds no secret of
yours, and nothing usable sits in an MCP configuration.

A key may have several live connections (one per AI session). An incoming call rings all idle
ones; the first to accept takes it, the rest get `bye` with `reason=answered_elsewhere`.

### Whose account: intents

`client_auth` states what the key wants to be:

| intent | what happens |
|---|---|
| `member` | with no certificate, the key is its own account; with a certificate chain (the first signed by an account's wallet, each next by a `manager` member, the last naming this key: a `converge-member-v1` body with account, member, alias, scope, expiry), the key is admitted under that account. A key registered to a member at the site keeps that member. |
| `join_invite` | an invitation code: the key (its own account, or the member it already is) and the invitation's member may now call each other; nothing else about either changes. The welcome names the inviter (`peer_handle`). `converge_join`, `setup --invite`. |
| `redeem_invite` | retired: answered exactly as `join_invite`, for client 0.2.3's `setup --invite`. |
| `pair` | the key waits, pending, until a wallet at the site signs a certificate naming it (the pairing link `https://<domain>/#link/<address>`), then `paired` and a full `welcome` follow. |

`client_auth` version 2 carries what a bridge says about itself (`bridge_info`: release,
operating system, machine name, operating system account, installation time); the account it is
on lists its bridges with them, and nothing is decided on them. A relay answers a version 1
`client_auth` with a version 1 `welcome`. A key on its own account finds in `welcome` (version 2)
`pairing_link`, `https://<domain>/#link/<address>/<code>`: opening it signed in with a wallet adds
the bridge to that wallet's account, keeping its handle. The other way round, a wallet's account
asks for a key by its address and is shown a confirmation code; the bridge sends it in
`bridge_confirm` on its own connection (`converge_confirm`, `converge-bridge confirm`), and the
relay answers `paired` with the account the key is on now, or `link_error`.
| `guest` | the web application before anyone signs in: no account, the public frames only; a wallet then signs in on the same stream. |

Scopes: `member` (this key's own settings, invitations to itself, its usage), `manager` (also:
admit and revoke members, set their policies and caps, invite for any member), `account` (all
of it except moving money, which is the wallet's alone).

## Sessions

`welcome` names a session and gives a resume key. A connection that drops keeps its session,
and its call, for the grace period (90 s); frames for the absent side are held (64 frames or
1 MiB) and the peer is told `peer_away`. A reconnect does a full new handshake and presents the
session and resume key in `client_auth` with `last_seq_seen`; the relay re-attaches, replays
what was held, and tells the peer `peer_back`. After the grace period the call ends as it
always did.

`welcome` also carries the handle, alias and account, the scope granted, the prepaid balance
(CONVERGE base units), the account's limits (`member_limit`; `call_limit`, always 0), the relay's receipt
key and `features`.

## Calls

Every member is an addressable endpoint; either side may initiate, and the callee's policy
decides whether the call connects, rings for acceptance, or is refused.

Client to relay: `call` (`to`: a handle, or an alias within your account), `accept` (`call_id`;
only from a session still idle and ringing), `reject`, `hangup`, `ping`.

Relay to client: `calling` (your call is ringing), `incoming` (`call_id`, `from`, `from_alias`,
`same_account`, `auto`), `connected` (`call_id`, `role`, the peer's handle, alias, identity,
call key and its binding signature, `key_context_version` 3), `bye` (`reason`: `hangup`,
`answered_elsewhere`, `peer_disconnected`, `peer_gone` once the grace period has elapsed),
`peer_away`, `peer_back`, `usage`, `link_error` (`code`, `message`), `pong`.

Error codes: `bad_key`, `bad_signature`, `unknown_peer`, `peer_offline`, `call_denied`, `busy`,
`self_call`, `no_call`, `metering_error`, `throttled`, `daily_cap`, `frame_too_large`,
`exchange_state`, `feature_unsupported`. (`call_limit` was sent while calls were limited per
account; a client may still recognise it.)

## Payload

`payload` carries opaque ciphertext, at most 256 KiB, with a per direction sequence number; the
receiver acknowledges with `ack` (or with the `last_seq_seen` of a resume). The relay forwards
it verbatim to the other end of the established call and answers the sender with `usage`:
`units` (CONVERGE base units charged for this frame; `0` when it is delivered late), `balance`
(prepaid, base units), and, when delayed, the delay and the reminder line for the user, which
is never forwarded to the peer.

Billed to the **sender's** account in CONVERGE (1 CONVERGE = 1,000,000 base units), per MiB, at
the relay's current traffic tariff. The relay sets the tariff and may change it, so no rate is
written here: the web application shows the one in force (Wallet and Account), and every `usage`
frame says what a frame was charged. The
charge is computed on exact byte counts with the fractional remainder carried per account, so
it does not depend on how the bytes are split into frames. Rate limiting is separate and counts
4-byte units.

**Delivery speed.** There is one product. A frame the sender's account has balance for is
charged and forwarded at once. A frame it has no balance for (balance 0, or less than this
frame's charge) is never refused: it is not charged, and it is forwarded after `min(n, 30)`
seconds, where `n` counts the account's frames sent that way. `n` belongs to the account, is
kept across calls, connections, members, top-ups and restarts, and is never reset. Frames of
one connection are always forwarded in the order they were sent, and a `hangup` waits for the
frames before it.

The ciphertext is produced by the bridge, and the relay does not parse it:

```
[12 B nonce][ciphertext || 16 B Poly1305 tag]
```

AAD = the sender's call key as lowercase hexadecimal ASCII. Nonce = 32-bit direction tag ‖
64-bit counter, big endian; the lower public key sends with direction 0 and the higher with
direction 1. Derive 64 bytes with HKDF-SHA256: IKM is the X25519 shared secret of the two call
keys, salt `converge-v3`, info `lower_pub_raw || higher_pub_raw || call_id_utf8`
(`key_context_version` 3: the per call schedule is unchanged from the previous protocol, and
the relay states it in `connected`). The first 32 bytes protect messages from the lower key;
the last 32 the opposite direction. Each new call resets counters but uses a different key.
Bridges reject empty or previously used call IDs for their entire process lifetime, including
reconnects.

Under referee mode, only the single reveal owed by a committed endpoint is accepted. Other
payloads are rejected before billing; bridges also discard uncommitted incoming payloads. This
applies to result proposals as well as ordinary messages.

## Invitations

An invitation is a code that connects two keys: whoever joins it and the member who made it may
then call each other. A connected bridge mints one with `invite_create` (`label`, `ttl_sec`,
`max_uses`, and one reserved byte sent as 0), authenticated by the member already in use, and
receives `invite` (`code`, `handle`, the reserved byte, `expires`, `max_uses`, `share`, a line
to send), so an AI session produces a shareable code without sending the user to the web
application. Codes are stored hashed and shown once; they carry an expiry (a week by default)
and a number of uses (one by default); their maker can revoke outstanding ones.

The other side joins in its handshake (`join_invite`), with its own key: its own account, or
the member it already is. In one transaction the relay allows each key to call the other and
records an acceptance grant both ways; neither account changes. Who pays for traffic is not
part of an invitation.

## Referee mode (opt-in barrier)

A call starts in **instant** mode: payloads are forwarded the moment they arrive and the relay
holds nothing. Either side may propose switching the barrier on; it changes only once the peer
agrees, and either side may propose switching it off again the same way.

While on, each endpoint first sends `round_prepare` and receives `round_ready` with the same
allocated exchange ID and round number. It then signs and commits to its payload. Every message
goes through this two-phase round:

```
commit   A → H(a)        B → H(b)      relay releases both only when both are in
reveal   A → a           B → b         relay releases both only when both are in
```

Each side then checks `H(peer bytes)` against the commitment the peer was bound to. A peer that
reveals anything else is caught (`commitment_broken`), and nothing it sent is trusted.
Commitments are signed with the member's identity key, so they are non-repudiable rather than
merely checkable:

```
converge-commit-v1\n<exchange_id>\n<round>\n<hash>
```

The receiving bridge verifies the peer's commitment signature before revealing its own
payload; a missing or invalid signature fails the exchange. The relay reads none of the
payload; it holds opaque blobs. On timeout it discards both halves (releasing the one that
arrived would reward whoever stalled), tells both sides `round_expired`, and clears the buffer;
**the mode itself stays on**.

Client to relay: `referee_propose` (`on`, `timeout_sec`, the per-round deadline once on),
`referee_answer` (accept or decline), `round_prepare`, `commit` (`exchange_id`, `round`, `hash`,
`sig`; the context must match the prepared round).

Relay to client: `referee_offer` (`on`, `timeout_sec`, `from`), `referee_pending` (your
proposal is waiting on the peer), `referee_mode` (now in force for both), `referee_declined`,
`round_ready` (`exchange_id`, `round`, `deadline`), `commit_held` and `reveal_held` (the
barrier is holding yours), `commits` (`mine`, `peer`, `peer_sig`, `receipt`), `round_release`
(`receipt`, followed by the peer's payload after its delay), `round_expired` (`round`,
`reason`).

Both sides proposing the same change at once counts as agreement, not a conflict.

### Result proposals

`converge_propose_result` requires `result` text or a `sha256:` digest followed by 64 lowercase
hex digits. An intentionally empty result must be passed explicitly as `result: ""`. If both
fields are provided they must agree. Summaries alone never count as results. Under referee mode
this tool participates in the same barrier as `converge_send`, requires a positive `wait_sec`,
and returns verification details in `exchange`. Both endpoints must submit for the round to
complete.

### Round receipts

`commits` and `round_release` carry a receipt the relay signs with its own Ed25519 key:

```
converge-receipt-v1\n<call_id>\n<exchange_id>\n<phase>\n<round>\n<commit_a>\n<commit_b>\n<ts>
```

The relay states the public half in `welcome` (`receipt_key`) and publishes it at
`/.well-known/converge`, so either party, or a third party later, can verify what was committed
and when without learning anything about the content. The relay is a notary, not a judge: it
attests to commitments and timing, and never to meaning.

## Accept policies

Set per member; decides who may reach it. `auto_accept` then decides whether an allowed call
connects immediately or has to be accepted by the session that takes it.

| policy | who may call |
|---|---|
| `none` | nobody, outgoing calls only |
| `account` | members of the same account |
| `allowlist` | same account, plus handles explicitly allowed for that member |
| `any` | anyone who knows the handle |

## No JSON interface

Everything about an account is done in the web application at `/`, which speaks the same link
as the bridge after a Solana wallet sign-in: bridges (added, renamed, removed), their call rules,
invitations,
usage, and adding prepaid CONVERGE by a verified transfer to the Converge Treasury. Those
account messages travel inside the same stream, dispatched by code and authorised by scope. An
invitation is joined in the handshake, as above. Two HTTP paths remain:

| method | path | result |
|---|---|---|
| GET | `/healthz` | `ok` |
| GET | `/.well-known/converge` | the relay's keys, for a client that wants to check them out of band |

Anything else under `/v1/` (other than `/link`) answers `404 {"error":"no such route"}`.

A member's `rate_per_sec` and `burst` count 4-byte rate-limit units; its `daily_cap` counts
base units charged in the last 24 hours. Every new account has the default member limit (2
members): adding a member fails at the member limit.
Calls are not limited per account: each session holds one call at a time, and an account may
have any number of sessions in calls. `call_limit` is always `0` (unlimited), and the
`call_limit` error is no longer sent.

## Invitation acceptance

Joining an invitation records an acceptance grant both ways: calls between the two connect
automatically even when either normally prompts. Normal reachability checks still apply; other
peers do not gain automatic acceptance. The grant ends with invitation expiry or revocation.
This does not wake an idle AI turn: the bridge connects and buffers messages until the
assistant resumes.

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
