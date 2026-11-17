/* pqsat_kdf.c  -  HMAC-SHA3-256 and HKDF over it, as the protocol specifies.
 *
 * HMAC per FIPS 198-1 with SHA3-256 as the hash.  SHA3-256 has a rate (block
 * size) of 136 octets, which is the value HMAC must use for key padding.
 * HKDF per RFC 5869, extract then expand, with HMAC-SHA3-256 as the PRF.
 *
 * Verified against Python's hmac module over hashlib.sha3_256 and against an
 * RFC 5869 style HKDF built from it, see test_kdf.py.
 */
#include <string.h>
#include <stdint.h>
#include "fips202.h"
#include "pqsat.h"

#define SHA3_256_RATE 136
#define SHA3_256_LEN  32

void pqsat_sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen)
{
    sha3_256(out, in, inlen);
}

void pqsat_hmac_sha3_256(uint8_t out[32], const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen)
{
    uint8_t k0[SHA3_256_RATE];
    uint8_t pad[SHA3_256_RATE];
    uint8_t inner[SHA3_256_LEN];
    sha3_256incctx st;
    size_t i;

    /* K0: hash a long key, zero pad to the rate */
    memset(k0, 0, sizeof k0);
    if (keylen > SHA3_256_RATE)
    {
        sha3_256(k0, key, keylen);
    }
    else
    {
        memcpy(k0, key, keylen);
    }

    /* inner = H((K0 xor ipad) || msg) */
    for (i = 0; i < SHA3_256_RATE; i++)
    {
        pad[i] = (uint8_t)(k0[i] ^ 0x36);
    }
    sha3_256_inc_init(&st);
    sha3_256_inc_absorb(&st, pad, SHA3_256_RATE);
    sha3_256_inc_absorb(&st, msg, msglen);
    sha3_256_inc_finalize(inner, &st); /* finalize releases the context */

    /* out = H((K0 xor opad) || inner) */
    for (i = 0; i < SHA3_256_RATE; i++)
    {
        pad[i] = (uint8_t)(k0[i] ^ 0x5c);
    }
    sha3_256_inc_init(&st);
    sha3_256_inc_absorb(&st, pad, SHA3_256_RATE);
    sha3_256_inc_absorb(&st, inner, SHA3_256_LEN);
    sha3_256_inc_finalize(out, &st);

    memset(k0, 0, sizeof k0);
    memset(pad, 0, sizeof pad);
    memset(inner, 0, sizeof inner);
}

/* HKDF-Extract then HKDF-Expand.  salt may be NULL (treated as 32 zero octets).
 * outlen up to 255 * 32.  Returns 0 on success. */
int pqsat_hkdf_sha3_256(uint8_t *out, size_t outlen, const uint8_t *salt, size_t saltlen, const uint8_t *ikm,
                        size_t ikmlen, const uint8_t *info, size_t infolen)
{
    uint8_t zero[SHA3_256_LEN];
    uint8_t prk[SHA3_256_LEN];
    uint8_t t[SHA3_256_LEN];
    uint8_t buf[SHA3_256_LEN + 255 + 1];
    size_t  tlen = 0, done = 0, n;
    uint8_t ctr;

    if (outlen > 255u * SHA3_256_LEN || infolen > 255)
    {
        return -1;
    }
    if (salt == NULL || saltlen == 0)
    {
        memset(zero, 0, sizeof zero);
        salt    = zero;
        saltlen = sizeof zero;
    }
    pqsat_hmac_sha3_256(prk, salt, saltlen, ikm, ikmlen);

    for (ctr = 1; done < outlen; ctr++)
    {
        memcpy(buf, t, tlen);
        memcpy(buf + tlen, info, infolen);
        buf[tlen + infolen] = ctr;
        pqsat_hmac_sha3_256(t, prk, SHA3_256_LEN, buf, tlen + infolen + 1);
        tlen = SHA3_256_LEN;
        n    = outlen - done;
        if (n > SHA3_256_LEN)
        {
            n = SHA3_256_LEN;
        }
        memcpy(out + done, t, n);
        done += n;
    }
    memset(prk, 0, sizeof prk);
    memset(t, 0, sizeof t);
    memset(buf, 0, sizeof buf);
    return 0;
}

/* The protocol's KDF(x, label): HKDF with no salt, input x, info label, 32 octets. */
void pqsat_kdf(uint8_t out[32], const uint8_t *x, size_t xlen, const char *label)
{
    (void)pqsat_hkdf_sha3_256(out, 32, NULL, 0, x, xlen, (const uint8_t *)label, strlen(label));
}
