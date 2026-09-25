/* TweetNaCl, compiled once for the link: X25519, Ed25519 and SHA-512 (which Ed25519 needs).
 * The reference is included as it was published (tweetnacl.c, public domain, 20140427); what is
 * added here is the randomness it asks for, from the operating system, and one derivation the
 * reference keeps inside its keypair function: the Ed25519 public key of a given seed. C, as the
 * reference is C. */
#include "tweetnacl.c"

#if defined(_WIN32)
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <bcrypt.h>
#pragma comment(lib, "bcrypt.lib")
#else
#include <unistd.h>
#if defined(__linux__)
#include <sys/random.h>
#endif
#endif
#include <stdlib.h>

void randombytes(u8* p, u64 n) {
#if defined(_WIN32)
    if (BCryptGenRandom(NULL, p, (ULONG)n, BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0) abort();
#else
    while (n) {
        unsigned take = n > 256 ? 256u : (unsigned)n;
        if (getentropy(p, take) != 0) abort();   /* no randomness is a reason to stop, never to continue */
        p += take; n -= take;
    }
#endif
}

/* The public key of an Ed25519 seed: what crypto_sign_keypair does after drawing the seed. */
int converge_ed25519_public_from_seed(unsigned char* pk, const unsigned char* seed) {
    u8 d[64];
    gf p[4];
    crypto_hash(d, seed, 32);
    d[0] &= 248; d[31] &= 127; d[31] |= 64;
    scalarbase(p, d);
    pack(pk, p);
    return 0;
}
