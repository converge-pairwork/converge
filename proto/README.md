# The CONVERGE link, protocol v4

This directory is the protocol: the frame format (`qsf.hpp`), every message (`link.hpp`), the
handshake and the sealed stream (`handshake.hpp`), certificates (`certificate.hpp`), and base58
(`base58.hpp`), and the primitives in portable C++ (`portable/`: X25519 and Ed25519 from TweetNaCl,
ChaCha20-Poly1305, SHA-256, HMAC and HKDF), with no dependency at all, so the web application
compiled to WebAssembly runs the same code as the relay and the bridge. `portable/nacl.c` is the
one file to compile beside the headers. The bridge builds against it here; the
relay and the web application take the same files from the client release, so that every end of
the link speaks from one definition. `tests/test_proto.cpp` is its whole test: messages round trip
strictly, a handshake between the two sides yields channels that talk, every tampering is refused,
certificates verify as specified, and every primitive agrees with OpenSSL on the published vectors
and on random inputs (the test is the only place OpenSSL is involved).

The QSF format originates in mm-studios/a0 (`base/kernel/include/a0/qsf`).

## One stream, any carrier

The link is an encrypted, authenticated byte stream. It does not depend on TLS: nothing on the
wire is readable or forgeable by whatever carries it. It runs over

- a WebSocket, `wss://<relay>/link` (or `ws://` to a local relay): one link frame per binary
  message. A relay tells v3 and v4 apart by the first message: a JSON text `hello` is v3, a binary
  frame is v4.
- a raw TCP socket: the four bytes `CVG4`, then each frame prefixed by its length as a u32 little
  endian. On port 443 a front proxy passes what is not a TLS ClientHello to the relay's raw
  listener, so this carrier shares the port with the site.

The bridge tries the raw carrier on 443 first and falls back to WSS: some networks only pass TLS
on 443. The web application uses WSS only, because a browser's wallet needs a secure context.

## Handshake

    client  ->  relay   client_hello      protocol 4, ephemeral X25519 key, 16 byte nonce, features, carrier   (plaintext)
    relay   ->  client  relay_hello       ephemeral key (plain); relay_hello_body sealed; a confirmation tag
    client  ->  relay   client_auth       the first sealed stream frame
    relay   ->  client  welcome | link_error

Key schedule, HKDF-SHA256 throughout, ChaCha20-Poly1305 for sealing:

    ee    = X25519(client ephemeral, relay ephemeral)
    ck1   = HKDF(salt "converge-v4", ikm ee, info "ck1")
    body  = AEAD(HKDF(ck1, "body"), nonce dir 1 counter 0, relay_hello_body, AD = SHA-256(m1 || relay ephemeral))
    es    = X25519(client ephemeral, relay static)
    ck2   = HKDF(salt ck1, ikm es, info "ck2")
    tag   = AEAD(HKDF(ck2, "confirm"), nonce dir 1 counter 0, "", AD = SHA-256(m1 || relay ephemeral || body))
    h     = SHA-256("converge-v4-transcript" || m1 || m2)
    k_c2r = HKDF(ck2, "c2r" || h)      k_r2c = HKDF(ck2, "r2c" || h)

`m1` and `m2` are the two frames exactly as sent. The relay's static key is sealed, so a passive
observer does not learn which relay this is; the confirmation tag needs `es`, which only the
holder of the static key can compute, so an impostor presenting the real public key cannot
finish. The client checks the static key against what it expects: the key pinned on first use,
or the one published at `/.well-known/converge` and in the site's configuration.

A stream frame is `AEAD(k_dir, nonce = dir(4) || counter(8) big endian, plaintext QSF frame, AD = h)`,
direction 0 client to relay, 1 relay to client. Counters start at 0 with every handshake and a
frame out of order is refused; the carrier delivers in order, so there is no window.

## Identity

An identity is an Ed25519 public key: 32 raw bytes on the wire, base58 in text, which is a Solana
address. A wallet is an identity like any other; a bridge's generated key is another. A handle is
a name for a key, derived from it: `cvh_` + the first 12 hex digits of SHA-256(key).

`client_auth` carries the identity, its signature over

    converge-v4-auth\n<domain>\n<identity base58>\n<h hex>\n<relay static key base58>

which binds it to this handshake, this relay and its name (so a signature obtained by one relay
is worthless at another, and a page cannot be tricked into signing for a different site), and a
per process X25519 call key with its signature over

    converge-session-v4\n<identity base58>\n<call key base58>

which the relay forwards in `connected`, so a peer can verify the call key came from that identity
and pin it. A wallet signs the same texts through `signMessage`; nothing binary is put in front of
a person.

### Whose account

- **No certificate:** the key is its own account, id = its address, balance 0, account scope.
  Nothing is registered first. This is how a session starts with no wallet at all.
- **A certificate chain:** the key is admitted under another account. The first certificate is
  signed by that account's wallet; each next one by the member the previous admitted with
  `manager` scope; the last names this key. A `converge-member-v1` body (`certificate.hpp`) names
  the account, the member, an alias, a scope and an expiry. A wallet signs it plainly
  (`signMessage`) or through Solana's off-chain message wrapper (`solana sign-offchain-message`);
  a verifier accepts either.
- **A wallet itself** authenticates the web application: no certificate, account scope, and the
  account is the wallet's.
- **Intent `pair`:** the key waits, pending, until the relay receives a certificate naming it
  (`certificate_submit` from a wallet session), then `paired` and a full `welcome` follow. This
  is the pairing link: the bridge prints `https://<domain>/#link/<its address>`, the page opens
  with the wallet connected, one approval signs the certificate.
- **Intent `redeem_invite` / `link_invite`:** as v3's invitation routes, inside the handshake.
- **Intent `guest`:** the web application before anyone signs in. No account, no member: the
  public frames only (the deployment facts, market data, the relay's key). A wallet then signs
  in on the same stream with the web application's `wallet_challenge_req` and `wallet_auth_req`
  (the Sign In With Solana text, signed once), which gives the stream account scope; the
  session it names resumes like any other.

Scopes: `member` (this key's own settings, invitations to itself, its usage), `manager` (also:
admit and revoke members, set their policies and caps, invite for any member), `account` (all of
it except moving money, which is the wallet's alone).

## Sessions

`welcome` names a session and gives a resume key. A connection that drops keeps its session, and
its call, for the grace period (90 s); frames for the absent side are held (64 frames or 1 MiB),
and the peer is told `peer_away`. A reconnect does a full new handshake and presents the session
and resume key in `client_auth` with `last_seq_seen`; the relay re-attaches, replays what was
held, and tells the peer `peer_back`. After the grace period the call ends as it always did.

Every `payload` carries a per direction sequence number; the receiver acknowledges with `ack` or
with the `last_seq_seen` of a resume. The relay answers the sender with `usage`: charged or
delayed, the balance after it, and the reminder line when delayed.

## Calls, payload, referee mode

As in v3, one frame per former JSON message: `call`, `calling`, `incoming`, `accept`, `reject`,
`hangup`, `connected`, `bye`, and the referee family (`referee_propose` and `referee_answer` from
a client; `referee_offer`, `referee_pending`, `referee_mode`, `referee_declined`, `round_ready`,
`commit_held`, `commits`, `reveal_held`, `release_held`, `round_release`, `round_expired` from the relay;
`round_prepare` and `commit` from a client). The peer payload sealing is v3's, unchanged (per
call keys, HKDF salt `converge-v3`, `key_context_version` 3): the relay forwards ciphertext it
cannot read. Commitment and receipt texts are v3's, unchanged.

## Account messages

The web application's account messages (`converge::wire`, codes 1 to 44: account, members,
invitations, usage, top-up, swap) travel inside the same stream. The relay dispatches on the
code and authorises by scope: a wallet session has account scope; a member key has member scope,
or what its certificate chain grants.
