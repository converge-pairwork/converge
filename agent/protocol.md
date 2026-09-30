# Wire protocol v4

The link between a CONVERGE client and the relay is **protocol v4**: one encrypted,
authenticated stream of binary QSF frames that does not depend on TLS, an Ed25519 identity that
is a Solana address, a key that is its own account until it is added to a wallet's, and sessions
that survive the socket. It is specified in
[proto/README.md](../proto/README.md) and defined by the headers beside it: `qsf.hpp` (the
frame format), `link.hpp` (every message), `handshake.hpp` (the handshake and the sealed
stream). The bridge, the relay and the web application compile the same headers, so every end of
the link speaks from one definition, and each message has one layout. This document is
the reference for an agent: what the link establishes, how invitations and calls
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
| **Identity key** | an Ed25519 keypair held by the bridge: 32 raw bytes on the wire, base58 in text, which is a Solana address. The bridge generates one on first run (`identity` in CONVERGE's state directory) and never sends the private half anywhere; `--print-identity` prints the public half as an `ssh-ed25519` line, the address and the handle. |
| **Handle** (`cvh_…`) | the public name others dial: `cvh_` plus the first 12 hex digits of SHA-256(public key). Derived, never assigned; safe to publish to whoever should be able to call. |
| **Name** | what the bridge is called on its account (the web application sets it). It is shown, never dialled. |
| **Account** | a Solana wallet's, or the key's own. A key is its own account from its first connection: balance 0, nothing registered first. The wallet's account adds it with the pairing link, or by its address and a code the bridge confirms. |

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

### Intents

`client_auth` states what the key wants, and what the bridge says about itself (`bridge_info`:
release, operating system, machine name, operating system account, installation time; the
account lists its bridges with them, and nothing is decided on them):

| intent | what happens |
|---|---|
| `member` | the key connects as what it is: its own account, or the bridge of the wallet's account it was added to. |
| `join_invite` | an invitation code: the key and the invitation's bridge are connected, and their calls to each other connect without asking; nothing else about either changes. The welcome names the inviter (`peer_handle`). `converge_join`, `setup --invite`. |
| `guest` | the web application before anyone signs in: no account, the public frames only; a wallet then signs in on the same stream. |

A key on its own account finds in `welcome` `pairing_link`,
`https://<domain>/#link/<address>/<code>`: opening it signed in with a wallet adds the bridge to
that wallet's account, keeping its handle. The other way round, a wallet's account asks for a
key by its address and is shown a confirmation code; the bridge sends it in `bridge_confirm` on
its own connection (`converge_confirm`, `converge-bridge confirm`), and the relay answers
`paired` (its name there, the wallet, the balance) or `link_error`.

## Sessions

`welcome` names a session and gives a resume key. A connection that drops keeps its session,
and its call, for the grace period (90 s); frames for the absent side are held (64 frames or
1 MiB) and the peer is told `peer_away`. A reconnect does a full new handshake and presents the
session and resume key in `client_auth` with `last_seq_seen`; the relay re-attaches, replays
what was held, and tells the peer `peer_back`. After the grace period the call ends as it
always did.

`welcome` also carries the handle and name, the account's prepaid balance (CONVERGE base units),
the Solana address of the wallet whose account the bridge is on (empty while it is its own), the
pairing link while it is its own and `features`.

## Calls

Every bridge is an addressable endpoint, and any bridge may call any other. A call connects at
once when the callee accepts calls automatically or the two joined an invitation; otherwise it
rings, and the callee's session accepts or rejects it.

Client to relay: `call` (`to`: a handle), `accept` (`call_id`;
only from a session still idle and ringing), `reject`, `hangup`, `ping`.

Relay to client: `calling` (your call is ringing), `incoming` (`call_id`, `from`, `from_alias`,
`auto`), `connected` (`call_id`, `role`, the peer's handle, name, identity, call key and its
binding signature), `bye` (`reason`: `hangup`,
`answered_elsewhere`, `peer_disconnected`, `peer_gone` once the grace period has elapsed),
`peer_away`, `peer_back`, `usage`, `terms`, `delivery`, `billing_request`, `billing_answer`,
`billing_prefs`, `link_error` (`code`, `message`), `pong`.

Error codes: `bad_key`, `bad_signature`, `unknown_peer`, `peer_offline`, `call_denied`, `busy`,
`self_call`, `no_call`, `metering_error`, `throttled`, `bad_request`, `frame_too_large`,
`feature_unsupported`.

## Payload

`payload` carries opaque ciphertext, at most 256 KiB, with a per direction sequence number; the
receiver acknowledges with `ack` (or with the `last_seq_seen` of a resume). The relay forwards
it verbatim to the other end of the established call and answers the sender with `usage`:
`units` (CONVERGE base units the sender's own account was charged for this frame; `0` when the
peer pays, nobody does, or it is delivered late), `balance` (that account's, base units),
`delayed` and `delay_ms`. It is never forwarded to the peer.

Billed to the **payer's** account (see Who pays) in CONVERGE (1 CONVERGE = 1,000,000 base units), per MiB, at
the relay's current traffic tariff. The relay sets the tariff and may change it, so no rate is written here: the web application shows the one in force (Wallet and Account),
and every `usage` frame says what a frame was charged. The charge is computed on exact byte
counts with the fractional remainder carried per paying account, so it does not depend on how
the bytes are split into frames. There is no daily cap. Rate limiting is separate and counts
4-byte units.

**Delivery speed.** There is one product. A frame whose payer's account has balance for it is
charged and forwarded at once. A frame nobody pays for, or whose payer has no balance for it
(balance 0, or less than this frame's charge), is never refused: it is not charged, and it is
forwarded after `min(n, cap)` seconds, where the cap is the relay's and `n` counts the frames
sent that way from this bridge to that one. `n` belongs to the pair of bridges and the
direction, never to an account, is kept across calls, connections, top-ups and restarts, and is
never reset. Frames of one connection are always forwarded in the order they were sent, and a
`hangup` waits for the frames before it.

## Who pays

A call's terms say who pays for each direction: the caller, the callee, or nobody. They come from
the two sides' **offers**, one per role: `none` (I pay nothing), `own` (I pay what I send) or
`all` (I pay both directions). A bridge's offer for a role is the first that is set of: its
connection with that peer, the bridge, its account (both set in the web application, the
connection and the bridge also by the bridge), and the built-in: `all` as caller, `none` as
callee. So by default the caller pays for the whole call.

Each direction is paid by whichever side offers to pay it: the sender with `own` or `all`, the
receiver with `all`. When both do, the offer from the more specific level wins (connection over
bridge over account over the built-in), then the more recent, then the caller's. When neither
does, nobody pays and that direction is delayed. A 50/50 split does not exist: each side pays
either what it sends or nothing, or the whole call.

"I pay" needs nobody's consent: a bridge sets its own offer with `billing_set` (`level` bridge,
or connection with `peer`, `""` for the current call's; `as_caller` and `as_callee` each `none`,
`own`, `all`, `inherit` to clear it, or `keep`). Stopping never moves the cost to the other side:
a direction nobody offers to pay is delayed. "You pay" does: `billing_offer` (`mine`, `yours`:
the offers the proposer would make for itself and asks of the peer) reaches the peer as
`billing_request`, whose user decides; `billing_answer` (`accept`) goes back to the proposer,
and accepting sets both connection preferences, each for its role in this call. One proposal is
open per call, and it lapses with the call. `billing_set` is answered by `billing_prefs`: the
bridge's preferences level by level, the offer in force per role and where it comes from.

Both sides get `terms` when the call connects and whenever it changes: `out` and `in` (who pays
what this side sends and what it receives: `me`, `peer` or `nobody`), this side's offer and its
level, and an open proposal. They get `delivery` at the same times and whenever a direction's
state changes: `out` and `in` (`paid`, `unpaid`: nobody pays, `payer_short`: the payer's balance
does not cover it), the delay the next frame each way would take, and this side's own account
only (`wallet`, empty for its own key's account, and `balance`); the peer's balance is never
disclosed. From it the bridge tells its user what would lift a delay: an account, a balance,
saying "I pay", asking the other side, or waiting.

Invitations carry nothing about who pays.

The ciphertext is produced by the bridge, and the relay does not parse it:

```
[12 B nonce][ciphertext || 16 B Poly1305 tag]
```

AAD = the sender's call key as lowercase hexadecimal ASCII. Nonce = 32-bit direction tag ‖
64-bit counter, big endian; the lower public key sends with direction 0 and the higher with
direction 1. Derive 64 bytes with HKDF-SHA256: IKM is the X25519 shared secret of the two call
keys, salt `converge-v3`, info `lower_pub_raw || higher_pub_raw || call_id_utf8`
(the per call schedule of the previous protocol, unchanged). The first 32 bytes protect messages from the lower key;
the last 32 the opposite direction. Each new call resets counters but uses a different key.
Bridges reject empty or previously used call IDs for their entire process lifetime, including
reconnects.

## Invitations

An invitation is a code that connects two keys: whoever joins it and the bridge that made it
answer each other's calls without asking. A connected bridge mints one with `invite_create`
(`ttl_sec`, `max_uses`) and receives `invite` (`code`, `handle`, `expires`, `max_uses`, `share`,
a line to send). It carries nothing about what the discussion is for: the topic goes in the
message the user sends, built on their machine, and never to the relay. That way an AI session produces a shareable code without sending the user to the web
application. Codes are stored hashed and shown once; they carry an expiry (a week by default)
and a number of uses (one by default); their maker can revoke outstanding ones.

The other side joins in its handshake (`join_invite`), with its own key, whatever account it is
on. In one transaction the relay records an acceptance grant both ways; neither account changes. Who pays for traffic is not
part of an invitation.

## Result proposals

`converge_propose_result` requires `result` text or a `sha256:` digest followed by 64 lowercase
hex digits. An intentionally empty result must be passed explicitly as `result: ""`. If both
fields are provided they must agree. Summaries alone never count as results.
Payloads are forwarded the moment they arrive; the relay holds nothing. Both sides converge when
they propose the same result in the same round.

## Accepting calls

Any bridge may call any other. Per bridge, `auto_accept` (set in the web application) decides
whether a call connects at once or rings for its session to accept; calls between two bridges
that joined an invitation connect at once either way.

## No JSON interface

Everything about an account is done in the web application at `/`, which speaks the same link
as the bridge after a Solana wallet sign-in: bridges (added, renamed, removed, auto-accept),
invitations, usage, and adding prepaid CONVERGE by a verified transfer to the Converge Treasury. Those
account messages travel inside the same stream, dispatched by code: a wallet's session does all
of them for its account; a bridge may create and revoke its own invitations. An
invitation is joined in the handshake, as above. Two HTTP paths remain:

| method | path | result |
|---|---|---|
| GET | `/healthz` | `ok` |
| GET | `/.well-known/converge` | the relay's keys, for a client that wants to check them out of band |

Anything else under `/v1/` (other than `/link`) answers `404 {"error":"no such route"}`.

A bridge's `rate_per_sec` and `burst` count 4-byte rate-limit units. There is no daily cap. An
account holds any number of bridges, and any number of calls: each session holds one call at a
time.

## Invitation acceptance

Joining an invitation records an acceptance grant both ways: calls between the two connect
automatically even when either normally prompts; other peers do not gain automatic acceptance. The grant ends with invitation expiry or revocation.

The inviter places the call. When someone joins, the relay has an idle session of the inviting
bridge call the joiner's (never the connection that only joined), at once, or as soon as both
have one, until that call connects or the invitation expires. If the one who joined calls the
inviter before that call came, the relay places it from the inviter instead: the first call of
an invitation is always the inviter's, whoever arrives first, so under the default terms (the
caller pays) the inviter pays for it. After it has connected, whoever calls is the caller. The
inviting bridge sees `calling` and `connected` as for any call it places.
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
