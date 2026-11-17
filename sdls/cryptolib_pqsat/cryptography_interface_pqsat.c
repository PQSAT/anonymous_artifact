/*
 * CryptoLib cryptography backend over libpqsat.
 *
 * NASA CryptoLib performs the CCSDS SDLS (355.0) frame processing: security
 * header and trailer, security association lookup, IV and anti replay checks,
 * authenticated data.  This file supplies only the cipher, AES-256-GCM, from
 * libpqsat (PQClean AES-256 with the SP 800-38D GCM in pqsat_gcm.c), so the
 * satellite and the ground use the same verified cipher code that the post
 * quantum handshake uses for its wraps.
 *
 * Supported: AEAD AES-256-GCM, 96 bit IV, 128 bit tag, encrypt and
 * authenticate, with or without additional authenticated data.  Everything
 * else is refused with the CryptoLib error for an unsupported suite, so a
 * misconfigured security association fails loudly instead of silently.
 */
#include <string.h>

#include "crypto.h"
#include "crypto_error.h"
#include "cryptography_interface.h"
#include "pqsat.h"

static CryptographyInterfaceStruct cryptography_if_struct;

static int32_t pq_config(void)
{
    return CRYPTO_LIB_SUCCESS;
}

static int32_t pq_init(void)
{
    return CRYPTO_LIB_SUCCESS;
}

static int32_t pq_shutdown(void)
{
    return CRYPTO_LIB_SUCCESS;
}

static int32_t pq_check(const uint8_t *ecs, uint32_t len_key, uint32_t iv_len, uint32_t mac_size)
{
    if (ecs == NULL)
    {
        return CRYPTO_LIB_ERR_NULL_ECS_PTR;
    }
    if (*ecs != CRYPTO_CIPHER_AES256_GCM || len_key != 32 || iv_len != 12 || mac_size != 16)
    {
        return CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
    }
    return CRYPTO_LIB_SUCCESS;
}

static int32_t pq_aead_encrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                               uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                               uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad, uint32_t aad_len,
                               uint8_t encrypt_bool, uint8_t authenticate_bool, uint8_t aad_bool, uint8_t *ecs,
                               uint8_t *acs, char *cam_cookies)
{
    uint8_t tag[16];
    int32_t st = pq_check(ecs, len_key, iv_len, mac_size);

    (void)sa_ptr;
    (void)acs;
    (void)cam_cookies;
    if (st != CRYPTO_LIB_SUCCESS)
    {
        return st;
    }
    if (encrypt_bool == CRYPTO_TRUE && len_data_out < len_data_in)
    {
        return CRYPTO_LIB_ERR_ENCRYPTION_ERROR;
    }
    /* GCM computes the tag over the ciphertext in any case; encrypt_bool false
       means authenticate only (GMAC over the AAD), which is a zero length
       plaintext. */
    pqsat_aes256gcm_encrypt(encrypt_bool == CRYPTO_TRUE ? data_out : NULL, tag, key, iv,
                            aad_bool == CRYPTO_TRUE ? aad : NULL, aad_bool == CRYPTO_TRUE ? aad_len : 0,
                            encrypt_bool == CRYPTO_TRUE ? data_in : NULL, encrypt_bool == CRYPTO_TRUE ? len_data_in : 0);
    if (authenticate_bool == CRYPTO_TRUE)
    {
        memcpy(mac, tag, 16);
    }
    return CRYPTO_LIB_SUCCESS;
}

static int32_t pq_aead_decrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                               uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                               uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad, uint32_t aad_len,
                               uint8_t decrypt_bool, uint8_t authenticate_bool, uint8_t aad_bool, uint8_t *ecs,
                               uint8_t *acs, char *cam_cookies)
{
    int32_t st = pq_check(ecs, len_key, iv_len, mac_size);

    (void)sa_ptr;
    (void)acs;
    (void)cam_cookies;
    if (st != CRYPTO_LIB_SUCCESS)
    {
        return st;
    }
    /* decryption without tag verification is never offered */
    if (authenticate_bool != CRYPTO_TRUE)
    {
        return CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
    }
    if (decrypt_bool == CRYPTO_TRUE && len_data_out < len_data_in)
    {
        return CRYPTO_LIB_ERR_DECRYPT_ERROR;
    }
    if (pqsat_aes256gcm_decrypt(decrypt_bool == CRYPTO_TRUE ? data_out : NULL, key, iv,
                                aad_bool == CRYPTO_TRUE ? aad : NULL, aad_bool == CRYPTO_TRUE ? aad_len : 0,
                                decrypt_bool == CRYPTO_TRUE ? data_in : NULL,
                                decrypt_bool == CRYPTO_TRUE ? len_data_in : 0, mac) != 0)
    {
        if (decrypt_bool == CRYPTO_TRUE)
        {
            memset(data_out, 0, len_data_in); /* never hand back unauthenticated plaintext */
        }
        return CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR;
    }
    return CRYPTO_LIB_SUCCESS;
}

/* Non AEAD paths are not used by the testbed's security associations. */
static int32_t pq_encrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in, uint8_t *key,
                          uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv, uint32_t iv_len, uint8_t *ecs,
                          uint8_t padding, char *cam_cookies)
{
    (void)data_out; (void)len_data_out; (void)data_in; (void)len_data_in; (void)key; (void)len_key;
    (void)sa_ptr; (void)iv; (void)iv_len; (void)ecs; (void)padding; (void)cam_cookies;
    return CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
}

static int32_t pq_decrypt(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in, uint8_t *key,
                          uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv, uint32_t iv_len, uint8_t *ecs,
                          uint8_t *acs, char *cam_cookies)
{
    (void)data_out; (void)len_data_out; (void)data_in; (void)len_data_in; (void)key; (void)len_key;
    (void)sa_ptr; (void)iv; (void)iv_len; (void)ecs; (void)acs; (void)cam_cookies;
    return CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
}

static int32_t pq_authenticate(uint8_t *data_out, size_t len_data_out, uint8_t *data_in, size_t len_data_in,
                               uint8_t *key, uint32_t len_key, SecurityAssociation_t *sa_ptr, uint8_t *iv,
                               uint32_t iv_len, uint8_t *mac, uint32_t mac_size, uint8_t *aad, uint32_t aad_len,
                               uint8_t ecs, uint8_t acs, char *cam_cookies)
{
    (void)data_out; (void)len_data_out; (void)data_in; (void)len_data_in; (void)key; (void)len_key;
    (void)sa_ptr; (void)iv; (void)iv_len; (void)mac; (void)mac_size; (void)aad; (void)aad_len; (void)ecs;
    (void)acs; (void)cam_cookies;
    return CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
}

static int32_t pq_validate_authentication(uint8_t *data_out, size_t len_data_out, const uint8_t *data_in,
                                          const size_t len_data_in, uint8_t *key, uint32_t len_key,
                                          SecurityAssociation_t *sa_ptr, const uint8_t *iv, uint32_t iv_len,
                                          const uint8_t *mac, uint32_t mac_size, const uint8_t *aad, uint32_t aad_len,
                                          uint8_t ecs, uint8_t acs, char *cam_cookies)
{
    (void)data_out; (void)len_data_out; (void)data_in; (void)len_data_in; (void)key; (void)len_key;
    (void)sa_ptr; (void)iv; (void)iv_len; (void)mac; (void)mac_size; (void)aad; (void)aad_len; (void)ecs;
    (void)acs; (void)cam_cookies;
    return CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
}

static int32_t pq_get_acs_algo(int8_t algo_enum)
{
    return (algo_enum == CRYPTO_MAC_NONE) ? 0 : CRYPTO_LIB_ERR_UNSUPPORTED_ACS;
}

static int32_t pq_get_ecs_algo(int8_t algo_enum)
{
    return (algo_enum == CRYPTO_CIPHER_AES256_GCM) ? (int32_t)CRYPTO_CIPHER_AES256_GCM : CRYPTO_LIB_ERR_UNSUPPORTED_ECS;
}

CryptographyInterface get_cryptography_interface_custom(void)
{
    cryptography_if_struct.cryptography_config                  = pq_config;
    cryptography_if_struct.cryptography_init                    = pq_init;
    cryptography_if_struct.cryptography_shutdown                = pq_shutdown;
    cryptography_if_struct.cryptography_encrypt                 = pq_encrypt;
    cryptography_if_struct.cryptography_decrypt                 = pq_decrypt;
    cryptography_if_struct.cryptography_authenticate            = pq_authenticate;
    cryptography_if_struct.cryptography_validate_authentication = pq_validate_authentication;
    cryptography_if_struct.cryptography_aead_encrypt            = pq_aead_encrypt;
    cryptography_if_struct.cryptography_aead_decrypt            = pq_aead_decrypt;
    cryptography_if_struct.cryptography_get_acs_algo            = pq_get_acs_algo;
    cryptography_if_struct.cryptography_get_ecs_algo            = pq_get_ecs_algo;
    return &cryptography_if_struct;
}
