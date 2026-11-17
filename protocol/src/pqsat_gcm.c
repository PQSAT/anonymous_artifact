/* pqsat_gcm.c  -  AES-256-GCM, NIST SP 800-38D, over the PQClean AES-256 core.
 *
 * Only the 96 bit nonce form is supported, which is all the protocol uses.
 * GHASH uses the bitwise multiplication of SP 800-38D Algorithm 1 written with
 * masks so that control flow does not depend on key material.
 *
 * Verified against the SP 800-38D example vectors and by differential testing
 * against an independent implementation (Python cryptography), see test_gcm.py.
 * Those tests are the evidence that this file is correct; do not change it
 * without rerunning them.
 */
#include <string.h>
#include <stdint.h>
#include "aes.h"
#include "pqsat.h"

typedef struct
{
    uint64_t hi, lo; /* big endian 128 bit block: hi holds octets 0..7 */
} blk_t;

static blk_t load(const uint8_t b[16])
{
    blk_t x;
    int   i;
    x.hi = x.lo = 0;
    for (i = 0; i < 8; i++)
    {
        x.hi = (x.hi << 8) | b[i];
        x.lo = (x.lo << 8) | b[8 + i];
    }
    return x;
}

static void store(uint8_t b[16], blk_t x)
{
    int i;
    for (i = 7; i >= 0; i--)
    {
        b[i]     = (uint8_t)(x.hi & 0xFF);
        b[8 + i] = (uint8_t)(x.lo & 0xFF);
        x.hi >>= 8;
        x.lo >>= 8;
    }
}

/* Z = X * Y in GF(2^128) with the GCM reduction polynomial, SP 800-38D 6.3. */
static blk_t gf_mul(blk_t x, blk_t y)
{
    blk_t    z = {0, 0};
    blk_t    v = y;
    int      i;
    uint64_t bit, lsb, m;

    for (i = 0; i < 128; i++)
    {
        bit = (i < 64) ? (x.hi >> (63 - i)) & 1u : (x.lo >> (127 - i)) & 1u;
        m   = 0u - bit;
        z.hi ^= v.hi & m;
        z.lo ^= v.lo & m;

        lsb  = v.lo & 1u;
        v.lo = (v.lo >> 1) | (v.hi << 63);
        v.hi = v.hi >> 1;
        v.hi ^= 0xE100000000000000ull & (0u - lsb); /* R = 11100001 || 0^120 */
    }
    return z;
}

static void ghash_update(blk_t *y, blk_t h, const uint8_t *data, size_t len)
{
    uint8_t tmp[16];
    blk_t   x;

    while (len >= 16)
    {
        x = load(data);
        y->hi ^= x.hi;
        y->lo ^= x.lo;
        *y = gf_mul(*y, h);
        data += 16;
        len -= 16;
    }
    if (len)
    {
        memset(tmp, 0, 16);
        memcpy(tmp, data, len);
        x = load(tmp);
        y->hi ^= x.hi;
        y->lo ^= x.lo;
        *y = gf_mul(*y, h);
    }
}

static void inc32(uint8_t ctr[16])
{
    uint32_t c = ((uint32_t)ctr[12] << 24) | ((uint32_t)ctr[13] << 16) | ((uint32_t)ctr[14] << 8) | ctr[15];
    c++;
    ctr[12] = (uint8_t)(c >> 24);
    ctr[13] = (uint8_t)(c >> 16);
    ctr[14] = (uint8_t)(c >> 8);
    ctr[15] = (uint8_t)c;
}

/* Shared core: CTR encrypt or decrypt `len` octets, and compute the tag over
 * aad and the ciphertext.  `ct` is the ciphertext whichever direction we run. */
static void gcm_core(const aes256ctx *ctx, const uint8_t nonce[12], const uint8_t *aad, size_t aadlen,
                     const uint8_t *in, uint8_t *out, size_t len, int encrypt, uint8_t tag[16])
{
    uint8_t h[16], j0[16], ctr[16], ks[16], lenblk[16], ej0[16];
    blk_t   hb, y = {0, 0};
    size_t  i, n;
    uint64_t abits = (uint64_t)aadlen * 8u, cbits = (uint64_t)len * 8u;

    memset(h, 0, 16);
    aes256_ecb(h, h, 1, ctx);
    hb = load(h);

    memcpy(j0, nonce, 12);
    j0[12] = j0[13] = j0[14] = 0;
    j0[15] = 1;
    memcpy(ctr, j0, 16);

    ghash_update(&y, hb, aad, aadlen);

    /* CTR mode over the data, hashing ciphertext blocks as they are produced or consumed */
    for (i = 0; i < len; i += 16)
    {
        inc32(ctr);
        aes256_ecb(ks, ctr, 1, ctx);
        n = len - i;
        if (n > 16)
        {
            n = 16;
        }
        if (encrypt)
        {
            for (size_t k = 0; k < n; k++)
            {
                out[i + k] = (uint8_t)(in[i + k] ^ ks[k]);
            }
            ghash_update(&y, hb, out + i, n);
        }
        else
        {
            ghash_update(&y, hb, in + i, n);
            for (size_t k = 0; k < n; k++)
            {
                out[i + k] = (uint8_t)(in[i + k] ^ ks[k]);
            }
        }
    }

    /* length block */
    for (i = 0; i < 8; i++)
    {
        lenblk[i]     = (uint8_t)(abits >> (56 - 8 * i));
        lenblk[8 + i] = (uint8_t)(cbits >> (56 - 8 * i));
    }
    ghash_update(&y, hb, lenblk, 16);

    aes256_ecb(ej0, j0, 1, ctx);
    store(tag, y);
    for (i = 0; i < 16; i++)
    {
        tag[i] ^= ej0[i];
    }
    memset(ks, 0, 16);
    memset(h, 0, 16);
}

void pqsat_aes256gcm_encrypt(uint8_t *ct, uint8_t tag[16], const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t ptlen)
{
    aes256ctx ctx;
    aes256_ecb_keyexp(&ctx, key);
    gcm_core(&ctx, nonce, aad, aadlen, pt, ct, ptlen, 1, tag);
    aes256_ctx_release(&ctx);
}

/* Returns 0 when the tag verifies, nonzero otherwise.  On failure the output
 * buffer is zeroed so a caller cannot use unauthenticated plaintext. */
int pqsat_aes256gcm_decrypt(uint8_t *pt, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
                            size_t aadlen, const uint8_t *ct, size_t ctlen, const uint8_t tag[16])
{
    aes256ctx ctx;
    uint8_t   t[16];
    uint8_t   diff = 0;
    int       i;

    aes256_ecb_keyexp(&ctx, key);
    gcm_core(&ctx, nonce, aad, aadlen, ct, pt, ctlen, 0, t);
    aes256_ctx_release(&ctx);
    for (i = 0; i < 16; i++)
    {
        diff |= (uint8_t)(t[i] ^ tag[i]);
    }
    if (diff)
    {
        memset(pt, 0, ctlen);
        return -1;
    }
    return 0;
}
