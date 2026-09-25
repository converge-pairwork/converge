"""Ed25519 for the release tooling and the tests: verification, and signing with a throwaway
key. Development-side only; nothing here is installed on a user's machine (the bridge carries
its own verifier, proto/portable, compiled in).

The verifier is the standard reference formulation of RFC 8032 and nothing more: it only ever
says yes or no about a signature. `release_keys()` reads the keys the bridge pins out of its
own source (bridge/src/release_key.hpp), so a tool asking "would an installed client accept
this release?" asks against exactly what the client carries.
"""
import base64
import hashlib
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
KEY_HEADER = ROOT / 'bridge' / 'src' / 'release_key.hpp'

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = -121665 * pow(121666, P - 2, P) % P
I = pow(2, (P - 1) // 4, P)


def _recover_x(y, sign):
    xx = (y * y - 1) * pow(D * y * y + 1, P - 2, P)
    x = pow(xx, (P + 3) // 8, P)
    if (x * x - xx) % P != 0:
        x = x * I % P
    if (x * x - xx) % P != 0:
        return None
    if x & 1 != sign:
        x = P - x
    return x


def _add(a, b):
    x1, y1, z1, t1 = a
    x2, y2, z2, t2 = b
    A = (y1 - x1) * (y2 - x2) % P
    B = (y1 + x1) * (y2 + x2) % P
    C = t1 * 2 * D * t2 % P
    E = z1 * 2 * z2 % P
    F, G, H, J = B - A, E - C, E + C, B + A
    return (F * G % P, H * J % P, G * H % P, F * J % P)


def _scalar_mult(point, e):
    result = (0, 1, 1, 0)
    while e > 0:
        if e & 1:
            result = _add(result, point)
        point = _add(point, point)
        e >>= 1
    return result


_BY = 4 * pow(5, P - 2, P) % P
BASE = (_recover_x(_BY, 0), _BY, 1, _recover_x(_BY, 0) * _BY % P)


def decode_point(data):
    if len(data) != 32:
        return None
    number = int.from_bytes(data, 'little')
    y = number & ((1 << 255) - 1)
    x = _recover_x(y, number >> 255)
    return None if x is None else (x, y, 1, x * y % P)


def encode_point(point):
    x = point[0] * pow(point[2], P - 2, P) % P
    y = point[1] * pow(point[2], P - 2, P) % P
    return (y | ((x & 1) << 255)).to_bytes(32, 'little')


def verify(public_key, signature, message):
    """True only when `signature` is a valid Ed25519 signature of `message` by `public_key`.
    Every malformed input is a False, never an exception."""
    try:
        if len(public_key) != 32 or len(signature) != 64:
            return False
        point = decode_point(public_key)
        r = decode_point(signature[:32])
        if point is None or r is None:
            return False
        s = int.from_bytes(signature[32:], 'little')
        if s >= L:
            return False
        h = int.from_bytes(hashlib.sha512(signature[:32] + public_key + message).digest(), 'little') % L
        left = _scalar_mult(BASE, s)
        right = _add(r, _scalar_mult(point, h))
        return encode_point(left) == encode_point(right)
    except Exception:
        return False


def keypair(seed):
    """(secret scalar, prefix, public key bytes) for a 32-byte seed. Tests only."""
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], 'little')
    a &= (1 << 254) - 8
    a |= 1 << 254
    return a, h[32:], encode_point(_scalar_mult(BASE, a))


def sign(seed, message):
    a, prefix, public = keypair(seed)
    r = int.from_bytes(hashlib.sha512(prefix + message).digest(), 'little') % L
    R = encode_point(_scalar_mult(BASE, r))
    k = int.from_bytes(hashlib.sha512(R + public + message).digest(), 'little') % L
    return R + ((r + k * a) % L).to_bytes(32, 'little')


def release_keys():
    """The base64 keys pinned in the bridge, newest first, as its source states them."""
    text = KEY_HEADER.read_text(encoding='utf-8')
    body = text.split('keys[] = {', 1)[1].split('};', 1)[0]
    return re.findall(r'"([A-Za-z0-9+/=]+)"', body)


def signed_by_converge(manifest_bytes, signature_text, keys=None):
    """Does this manifest verify against a pinned key? None when no key is pinned, so that an
    unsigned release is never reported as authentic."""
    keys = release_keys() if keys is None else keys
    if not keys:
        return None
    try:
        signature = base64.b64decode(signature_text.split()[0], validate=True)
    except Exception:
        return False
    for key in keys:
        try:
            public = base64.b64decode(key, validate=True)
        except Exception:
            continue
        if len(public) == 32 and verify(public, signature, manifest_bytes):
            return True
    return False
