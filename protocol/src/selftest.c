/* selftest.c  -  runs on the target (Versal A72) to prove the library and to
 * time every primitive the protocol uses, from inside C, with no Python.
 * Prints one line per primitive: name, octets, mean microseconds, iterations.
 */
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <stdlib.h>
#include "pqsat.h"

int PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                                const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                             const uint8_t *pk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(uint8_t *pk, uint8_t *sk);
int PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                                  const uint8_t *sk);
int PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                               const uint8_t *pk);

static double now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e6 + (double)t.tv_nsec / 1e3;
}

#define TIME(label, octets, iters, body)                                                                     \
    do                                                                                                       \
    {                                                                                                        \
        double t0 = now_us();                                                                                \
        for (int _i = 0; _i < (iters); _i++)                                                                 \
        {                                                                                                    \
            body;                                                                                            \
        }                                                                                                    \
        printf("%-22s %6d B  %10.1f us  x%d\n", label, (int)(octets), (now_us() - t0) / (iters), (iters));  \
    } while (0)

int main(int argc, char **argv)
{
    int iters = argc > 1 ? atoi(argv[1]) : 20;
    static uint8_t dpk[PQSAT_MLDSA65_PK], dsk[PQSAT_MLDSA65_SK], sig[PQSAT_MLDSA65_SIG];
    static uint8_t kpk[PQSAT_MLKEM768_PK], ksk[PQSAT_MLKEM768_SK], ct[PQSAT_MLKEM768_CT], ss1[32], ss2[32];
    static uint8_t fpk[PQSAT_FALCON512_PK], fsk[PQSAT_FALCON512_SK], fsig[PQSAT_FALCON512_SIG];
    uint8_t msg[310], h[32], mac[32], key[32], nonce[12], wrap[32], tag[16], out[32];
    size_t  siglen = 0, fsiglen = 0;
    int     ok = 1;

    memset(msg, 0x42, sizeof msg);
    memset(key, 0x11, sizeof key);
    memset(nonce, 0x22, sizeof nonce);

    printf("pqsat self test, %d iterations per primitive\n", iters);
    TIME("ML-DSA-65 keygen", PQSAT_MLDSA65_PK, iters, PQCLEAN_MLDSA65_CLEAN_crypto_sign_keypair(dpk, dsk));
    TIME("ML-DSA-65 sign", PQSAT_MLDSA65_SIG, iters,
         PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, &siglen, msg, 32, dsk));
    TIME("ML-DSA-65 verify", PQSAT_MLDSA65_SIG, iters,
         ok &= (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, siglen, msg, 32, dpk) == 0));
    TIME("ML-KEM-768 keygen", PQSAT_MLKEM768_PK, iters, PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(kpk, ksk));
    TIME("ML-KEM-768 encaps", PQSAT_MLKEM768_CT, iters, PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss1, kpk));
    TIME("ML-KEM-768 decaps", 32, iters, PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss2, ct, ksk));
    ok &= (memcmp(ss1, ss2, 32) == 0);
    TIME("Falcon-512 keygen", PQSAT_FALCON512_PK, iters > 5 ? 5 : iters,
         PQCLEAN_FALCON512_CLEAN_crypto_sign_keypair(fpk, fsk));
    TIME("Falcon-512 sign", 0, iters, PQCLEAN_FALCON512_CLEAN_crypto_sign_signature(fsig, &fsiglen, msg, 32, fsk));
    printf("%-22s %6d B  (actual signature length)\n", "Falcon-512 signature", (int)fsiglen);
    TIME("Falcon-512 verify", (int)fsiglen, iters,
         ok &= (PQCLEAN_FALCON512_CLEAN_crypto_sign_verify(fsig, fsiglen, msg, 32, fpk) == 0));
    TIME("SHA3-256 (310 B)", 32, iters * 50, pqsat_sha3_256(h, msg, sizeof msg));
    TIME("HMAC-SHA3-256 (32 B)", 32, iters * 50, pqsat_hmac_sha3_256(mac, key, 32, h, 32));
    TIME("KDF (HKDF, 32 B)", 32, iters * 50, pqsat_kdf(mac, ss1, 32, "HSig-MAC"));
    TIME("AES-256-GCM wrap 32 B", 48, iters * 50, pqsat_aes256gcm_encrypt(wrap, tag, key, nonce, NULL, 0, ss1, 32));
    TIME("AES-256-GCM unwrap", 32, iters * 50,
         ok &= (pqsat_aes256gcm_decrypt(out, key, nonce, NULL, 0, wrap, 32, tag) == 0));
    ok &= (memcmp(out, ss1, 32) == 0);

    printf("%s\n", ok ? "SELFTEST OK" : "SELFTEST FAILED");
    return ok ? 0 : 1;
}
