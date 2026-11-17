/* pqsat.h  -  the primitive layer shared by the flight software and the ground.
 *
 * Post quantum primitives come from PQClean (ML-DSA-65, ML-KEM-768, Falcon-512)
 * and are reached through their own exported names.  This header adds the
 * symmetric pieces the protocol needs on top of them.
 */
#ifndef PQSAT_H
#define PQSAT_H

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* FIPS 204 ML-DSA-65 */
#define PQSAT_MLDSA65_PK  1952
#define PQSAT_MLDSA65_SK  4032
#define PQSAT_MLDSA65_SIG 3309

/* FIPS 203 ML-KEM-768 */
#define PQSAT_MLKEM768_PK 1184
#define PQSAT_MLKEM768_SK 2400
#define PQSAT_MLKEM768_CT 1088
#define PQSAT_MLKEM768_SS 32

/* Falcon-512, comparison only */
#define PQSAT_FALCON512_PK  897
#define PQSAT_FALCON512_SK  1281
#define PQSAT_FALCON512_SIG 752 /* maximum, actual length varies */

void pqsat_sha3_256(uint8_t out[32], const uint8_t *in, size_t inlen);
void pqsat_hmac_sha3_256(uint8_t out[32], const uint8_t *key, size_t keylen, const uint8_t *msg, size_t msglen);
int  pqsat_hkdf_sha3_256(uint8_t *out, size_t outlen, const uint8_t *salt, size_t saltlen, const uint8_t *ikm,
                         size_t ikmlen, const uint8_t *info, size_t infolen);
/* KDF(x, label) as the protocol writes it: HKDF, no salt, info = label, 32 octets. */
void pqsat_kdf(uint8_t out[32], const uint8_t *x, size_t xlen, const char *label);

void pqsat_aes256gcm_encrypt(uint8_t *ct, uint8_t tag[16], const uint8_t key[32], const uint8_t nonce[12],
                             const uint8_t *aad, size_t aadlen, const uint8_t *pt, size_t ptlen);
int  pqsat_aes256gcm_decrypt(uint8_t *pt, const uint8_t key[32], const uint8_t nonce[12], const uint8_t *aad,
                             size_t aadlen, const uint8_t *ct, size_t ctlen, const uint8_t tag[16]);

#ifdef __cplusplus
}
#endif
#endif
