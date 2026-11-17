/* sat_auth.c  -  Phase 5 satellite role, C implementation.  See sat_auth.h. */
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include "sat_auth.h"
#include "pqsat.h"

/* PQClean entry points from libpqsat */
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(uint8_t *sig, size_t *siglen, const uint8_t *m, size_t mlen,
                                                const uint8_t *sk);
int PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(const uint8_t *sig, size_t siglen, const uint8_t *m, size_t mlen,
                                             const uint8_t *pk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(uint8_t *ct, uint8_t *ss, const uint8_t *pk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(uint8_t *ss, const uint8_t *ct, const uint8_t *sk);
int PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(uint8_t *pk, uint8_t *sk);

static double now_us(void)
{
    struct timespec t;
    clock_gettime(CLOCK_MONOTONIC, &t);
    return (double)t.tv_sec * 1e6 + (double)t.tv_nsec / 1e3;
}

static void say(Auth_Sat_t *a, const char *fmt, const char *arg)
{
    char buf[160];
    if (a->log)
    {
        snprintf(buf, sizeof buf, fmt, arg ? arg : "");
        a->log(buf, a->ctx);
    }
}

static void put16(uint8_t *p, uint16_t v)
{
    p[0] = (uint8_t)(v >> 8);
    p[1] = (uint8_t)v;
}
static void put32(uint8_t *p, uint32_t v)
{
    p[0] = (uint8_t)(v >> 24);
    p[1] = (uint8_t)(v >> 16);
    p[2] = (uint8_t)(v >> 8);
    p[3] = (uint8_t)v;
}
static uint16_t get16(const uint8_t *p)
{
    return (uint16_t)((p[0] << 8) | p[1]);
}
static uint32_t get32(const uint8_t *p)
{
    return ((uint32_t)p[0] << 24) | ((uint32_t)p[1] << 16) | ((uint32_t)p[2] << 8) | p[3];
}

static void random_bytes(uint8_t *out, size_t n)
{
    /* The library's randombytes reads the OS source; reuse it through a
     * throwaway KEM keypair would be wasteful, so read /dev/urandom directly. */
    FILE *f = fopen("/dev/urandom", "rb");
    if (f)
    {
        if (fread(out, 1, n, f) != n)
        {
            memset(out, 0x5A, n);
        }
        fclose(f);
    }
    else
    {
        memset(out, 0x5A, n);
    }
}

/* ---------------------------------------------------------------- certificates */

static void cert_parse(Auth_Cert_t *c, const uint8_t *b)
{
    const uint8_t *p = b;
    memcpy(c->bundle, b, AUTH_CERT_BUNDLE);
    c->ident = get16(p);
    p += 2;
    c->role = *p;
    p += 1;
    memcpy(c->pk_sigma, p, AUTH_DSA_PK);
    p += AUTH_DSA_PK;
    memcpy(c->pk_kappa, p, AUTH_KEM_PK);
    p += AUTH_KEM_PK;
    memcpy(c->omega, p, AUTH_HASH);
    p += AUTH_HASH;
    c->not_before = get32(p);
    p += 4;
    c->not_after = get32(p);
    pqsat_sha3_256(c->digest, b, AUTH_CERT_BODY);
    c->valid = false;
    c->installed = false;
    c->candidate = false;
}

/* A peer verifies the validity window and the authority's ML-DSA half.  The
 * KEM half can only be checked by the subject (Finding 3 in the spec). */
static bool cert_verify_peer(Auth_Sat_t *a, Auth_Cert_t *c, uint32_t now)
{
    const uint8_t *sigma = c->bundle + AUTH_CERT_BODY + AUTH_KEM_CT;
    double         t0    = now_us();
    bool           ok;

    if (now < c->not_before || now > c->not_after)
    {
        return false;
    }
    ok = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sigma, AUTH_DSA_SIG, c->digest, AUTH_HASH, a->ta_pk_sigma) == 0;
    a->t_cert_us += now_us() - t0;
    c->valid = ok;
    return ok;
}

/* The subject checks both halves of its own certificate at load time. */
static bool cert_verify_self(Auth_Sat_t *a, uint32_t now)
{
    Auth_Cert_t *c     = &a->self_cert;
    const uint8_t *cct = c->bundle + AUTH_CERT_BODY;
    const uint8_t *tau = c->bundle + AUTH_CERT_BODY + AUTH_KEM_CT + AUTH_DSA_SIG;
    uint8_t ss[AUTH_SS], k[32], mac[32];

    if (!cert_verify_peer(a, c, now))
    {
        return false;
    }
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, cct, a->sk_kappa);
    pqsat_kdf(k, ss, AUTH_SS, "cert-mac");
    pqsat_hmac_sha3_256(mac, k, 32, c->digest, AUTH_HASH);
    return memcmp(mac, tau, AUTH_TAG) == 0;
}

static int cert_field_encode(uint8_t *out, const Auth_Cert_t *c, bool full)
{
    if (full)
    {
        out[0] = AUTH_CERT_MODE_FULL;
        memcpy(out + 1, c->bundle, AUTH_CERT_BUNDLE);
        return 1 + AUTH_CERT_BUNDLE;
    }
    out[0] = AUTH_CERT_MODE_REF;
    put16(out + 1, c->ident);
    memcpy(out + 3, c->digest, AUTH_HASH);
    return 1 + AUTH_CERT_REF;
}

/* Returns the field length consumed, or -1 on a malformed field.  Sets *mode
 * and *payload. */
static int cert_field_decode(const uint8_t *b, int n, uint8_t *mode, const uint8_t **payload)
{
    if (n < 1)
    {
        return -1;
    }
    *mode = b[0];
    if (*mode == AUTH_CERT_MODE_FULL && n >= 1 + AUTH_CERT_BUNDLE)
    {
        *payload = b + 1;
        return 1 + AUTH_CERT_BUNDLE;
    }
    if (*mode == AUTH_CERT_MODE_REF && n >= 1 + AUTH_CERT_REF)
    {
        *payload = b + 1;
        return 1 + AUTH_CERT_REF;
    }
    return -1;
}

/* Resolve a certificate field into `slot`.  Returns 1 ok, 0 unknown reference
 * (caller sends a demand), -1 rejected. */
bool Auth_IsRevoked(const Auth_Sat_t *a, uint16_t ident)
{
    unsigned i;
    for (i = 0; i < a->n_revoked; i++)
    {
        if (a->revoked[i] == ident)
        {
            return true;
        }
    }
    return false;
}

int Auth_InstallCrl(Auth_Sat_t *a, const uint8_t *msg, int len)
{
    uint8_t  h[32];
    uint32_t issued;
    unsigned n, i;
    int      body;

    if (len < 2 + 6 + AUTH_DSA_SIG || msg[0] != SAT_AUTH_VERSION || msg[1] != AUTH_CRL)
    {
        return -1;
    }
    issued = get32(msg + 2);
    n      = get16(msg + 6);
    body   = 6 + 2 * (int)n;
    if (n > AUTH_REVOKED_MAX || len != 2 + body + AUTH_DSA_SIG)
    {
        say(a, "auth: revocation list malformed", NULL);
        return -1;
    }
    pqsat_sha3_256(h, msg + 2, (size_t)body);
    if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(msg + 2 + body, AUTH_DSA_SIG, h, 32, a->ta_pk_sigma) != 0)
    {
        say(a, "auth: revocation list rejected, signature of the authority does not verify", NULL);
        return -1;
    }
    if (issued <= a->crl_issued)
    {
        say(a, "auth: revocation list not newer than the one held, ignored", NULL);
        return -1;
    }
    a->crl_issued = issued;
    a->n_revoked  = n;
    for (i = 0; i < n; i++)
    {
        a->revoked[i] = get16(msg + 8 + 2 * i);
    }
    /* a cached certificate of a revoked identity is dropped at once */
    if (a->ue_cert.valid && Auth_IsRevoked(a, a->ue_cert.ident))
    {
        a->ue_cert.valid = false;
    }
    if (a->crl_path[0] != 0)
    {
        FILE *f = fopen(a->crl_path, "wb");
        if (f != NULL)
        {
            fwrite(msg, 1, (size_t)len, f);
            fclose(f);
        }
    }
    {
        char b[96];
        snprintf(b, sizeof b, "auth: revocation list installed, %u revoked, issued %u", n, (unsigned)issued);
        say(a, "%s", b);
    }
    return (int)n;
}

int Auth_LoadCrl(Auth_Sat_t *a, const char *path)
{
    static uint8_t buf[2 + 6 + 2 * AUTH_REVOKED_MAX + AUTH_DSA_SIG];
    FILE          *f = fopen(path, "rb");
    int            n;

    if (f == NULL)
    {
        return -1;
    }
    n = (int)fread(buf, 1, sizeof buf, f);
    fclose(f);
    return Auth_InstallCrl(a, buf, n);
}

static int cert_resolve(Auth_Sat_t *a, Auth_Cert_t *slot, uint8_t mode, const uint8_t *payload, uint16_t expect,
                        uint8_t role, uint32_t now)
{
    if (Auth_IsRevoked(a, expect))
    {
        a->revoked_rejected++;
        say(a, "auth: identity is on the revocation list", NULL);
        return -1;
    }
    if (mode == AUTH_CERT_MODE_FULL)
    {
        Auth_Cert_t tmp;
        cert_parse(&tmp, payload);
        if (tmp.ident != expect || !cert_verify_peer(a, &tmp, now))
        {
            return -1;
        }
        if (tmp.role != role)
        {
            say(a, "auth: certificate role does not fit its place in the handshake", NULL);
            return -1;
        }
#ifndef AUTH_NO_CERT_PIN
        /* Certificate policy.  Validation and installation are separate.  A certificate that
         * was provisioned at enrollment is the trusted binding of that identity: a certificate
         * received in band is accepted only if it is that same certificate and never takes its
         * place.  Where no certificate is installed the one received is a candidate for this
         * handshake only and is dropped again if the handshake does not complete. */
        if (slot->valid && slot->installed && slot->ident == tmp.ident)
        {
            if (memcmp(slot->digest, tmp.digest, AUTH_HASH) != 0)
            {
                a->cert_pin_rejected++;
                say(a, "auth: certificate received in band differs from the installed one, rejected", NULL);
                return -1;
            }
            return 1;
        }
        tmp.installed = false;
        tmp.candidate = true;
#endif
        *slot = tmp;
        return 1;
    }
    if (!slot->valid || slot->ident != get16(payload) || memcmp(slot->digest, payload + 2, AUTH_HASH) != 0)
    {
        return 0;
    }
    return (slot->ident == expect && slot->role == role) ? 1 : -1;
}

/* ---------------------------------------------------------------- hybrid signatures */

static void hybrid_sign(Auth_Sat_t *a, uint8_t out[AUTH_HSIG], const uint8_t *ss, const uint8_t digest[32])
{
    size_t  siglen = 0;
    uint8_t k[32];
    double  t0 = now_us();
    PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(out, &siglen, digest, 32, a->sk_sigma);
    a->t_sign_us += now_us() - t0;
    pqsat_kdf(k, ss, AUTH_SS, "HSig-MAC");
    pqsat_hmac_sha3_256(out + AUTH_DSA_SIG, k, 32, digest, 32);
}

static bool hybrid_verify(Auth_Sat_t *a, const uint8_t *pk, const uint8_t *ss, const uint8_t digest[32],
                          const uint8_t hsig[AUTH_HSIG], bool require_kem)
{
    uint8_t k[32], mac[32];
    double  t0 = now_us();
    bool    ok = PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(hsig, AUTH_DSA_SIG, digest, 32, pk) == 0;
    a->t_verify_us += now_us() - t0;
    if (!ok || !require_kem)
    {
        return ok;
    }
    pqsat_kdf(k, ss, AUTH_SS, "HSig-MAC");
    pqsat_hmac_sha3_256(mac, k, 32, digest, 32);
    return memcmp(mac, hsig + AUTH_DSA_SIG, AUTH_TAG) == 0;
}

static bool verify_kem_half(const uint8_t *ss, const uint8_t digest[32], const uint8_t hsig[AUTH_HSIG])
{
    uint8_t k[32], mac[32];
    pqsat_kdf(k, ss, AUTH_SS, "HSig-MAC");
    pqsat_hmac_sha3_256(mac, k, 32, digest, 32);
    return memcmp(mac, hsig + AUTH_DSA_SIG, AUTH_TAG) == 0;
}

/* ---------------------------------------------------------------- wraps and tags */

static void wrap_nonce(uint8_t out[12], const Auth_Sat_t *a, const char *label)
{
    uint8_t buf[3 * AUTH_NONCE + 16], h[32];
    size_t  l = strlen(label);
    memcpy(buf, a->mu_u, AUTH_NONCE);
    memcpy(buf + AUTH_NONCE, a->mu_s, AUTH_NONCE);
    memcpy(buf + 2 * AUTH_NONCE, a->mu_g, AUTH_NONCE);
    memcpy(buf + 3 * AUTH_NONCE, label, l);
    pqsat_sha3_256(h, buf, 3 * AUTH_NONCE + l);
    memcpy(out, h, 12);
}

/* A wrap carries one session secret and one authentication secret, 64 octets. */
static void do_wrap(Auth_Sat_t *a, uint8_t out[AUTH_WRAP], const uint8_t *key, const char *label,
                    const uint8_t k[AUTH_SS], const uint8_t ss[AUTH_SS])
{
    uint8_t nonce[12], pt[2 * AUTH_SS];
    double  t0 = now_us();
    memcpy(pt, k, AUTH_SS);
    memcpy(pt + AUTH_SS, ss, AUTH_SS);
    wrap_nonce(nonce, a, label);
    pqsat_aes256gcm_encrypt(out, out + 2 * AUTH_SS, key, nonce, NULL, 0, pt, 2 * AUTH_SS);
    memset(pt, 0, sizeof pt);
    a->t_wrap_us += now_us() - t0;
}

static bool do_unwrap(Auth_Sat_t *a, uint8_t k[AUTH_SS], uint8_t ss[AUTH_SS], const uint8_t *key, const char *label,
                      const uint8_t blob[AUTH_WRAP])
{
    uint8_t nonce[12], pt[2 * AUTH_SS];
    bool    ok;
    wrap_nonce(nonce, a, label);
    ok = pqsat_aes256gcm_decrypt(pt, key, nonce, NULL, 0, blob, 2 * AUTH_SS, blob + 2 * AUTH_SS) == 0;
    if (ok)
    {
        memcpy(k, pt, AUTH_SS);
        memcpy(ss, pt + AUTH_SS, AUTH_SS);
    }
    memset(pt, 0, sizeof pt);
    return ok;
}

static void tag_of(uint8_t out[32], const uint8_t *k, size_t klen, const uint8_t *k2, size_t k2len,
                   const Auth_Sat_t *a, const char *label)
{
    uint8_t buf[64 + 3 * AUTH_NONCE + 16];
    size_t  n = 0, l = strlen(label);
    memcpy(buf + n, k, klen);
    n += klen;
    if (k2)
    {
        memcpy(buf + n, k2, k2len);
        n += k2len;
    }
    memcpy(buf + n, a->mu_u, AUTH_NONCE);
    n += AUTH_NONCE;
    memcpy(buf + n, a->mu_s, AUTH_NONCE);
    n += AUTH_NONCE;
    memcpy(buf + n, a->mu_g, AUTH_NONCE);
    n += AUTH_NONCE;
    memcpy(buf + n, label, l);
    n += l;
    pqsat_sha3_256(out, buf, n);
}

static void derive_sk(Auth_Sat_t *a)
{
    uint8_t buf[6 * AUTH_SS + 3 * AUTH_NONCE + 6 + AUTH_PI3];
    size_t  n = 0;
    /* the three ephemeral session secrets (forward secrecy) and the three authentication
     * secrets (authentication that does not depend on ML-DSA) */
    memcpy(buf + n, a->k_su, AUTH_SS); n += AUTH_SS;
    memcpy(buf + n, a->k_gs, AUTH_SS); n += AUTH_SS;
    memcpy(buf + n, a->k_gu, AUTH_SS); n += AUTH_SS;
    memcpy(buf + n, a->ss_us, AUTH_SS); n += AUTH_SS;
    memcpy(buf + n, a->ss_sg, AUTH_SS); n += AUTH_SS;
    memcpy(buf + n, a->ss_gu, AUTH_SS); n += AUTH_SS;
    memcpy(buf + n, a->mu_u, AUTH_NONCE); n += AUTH_NONCE;
    memcpy(buf + n, a->mu_s, AUTH_NONCE); n += AUTH_NONCE;
    memcpy(buf + n, a->mu_g, AUTH_NONCE); n += AUTH_NONCE;
    put16(buf + n, a->id_ue); n += 2;
    put16(buf + n, a->ident); n += 2;
    put16(buf + n, a->id_gs); n += 2;
    memcpy(buf + n, a->pi3, AUTH_PI3); n += AUTH_PI3;
    pqsat_kdf(a->sk, buf, n, "SK");
    memset(buf, 0, sizeof buf);
    /* have_sk is set only once the ground station's confirmation tag verifies */
}

/* Forward secrecy: forget the ephemeral secret key and every session and
 * authentication secret of this handshake.  SK itself stays for SDLS. */
static void erase_ephemeral(Auth_Sat_t *a)
{
    memset(a->esk_s, 0, sizeof a->esk_s);
    memset(a->k_su, 0, sizeof a->k_su);
    memset(a->k_gs, 0, sizeof a->k_gs);
    memset(a->k_gu, 0, sizeof a->k_gu);
    memset(a->ss_us, 0, sizeof a->ss_us);
    memset(a->ss_sg, 0, sizeof a->ss_sg);
    memset(a->ss_gu, 0, sizeof a->ss_gu);
    memset(a->w_sg, 0, sizeof a->w_sg);
    memset(a->c_su_g, 0, sizeof a->c_su_g);
}

/* ---------------------------------------------------------------- message builders */

static int build_msg2(Auth_Sat_t *a, uint8_t *out, bool full)
{
    uint8_t *p = out;
    uint8_t  h[32];
    p[0] = SAT_AUTH_VERSION;
    p[1] = AUTH_MSG2;
    p += 2;
    p += cert_field_encode(p, &a->ue_cert, full || a->ue_cert_full);
    pqsat_sha3_256(h, a->c_us, AUTH_KEM_CT);
    memcpy(p, h, 32); p += 32;
    memcpy(p, a->epk_u, AUTH_KEM_PK); p += AUTH_KEM_PK;
    memcpy(p, a->mu_u, AUTH_NONCE); p += AUTH_NONCE;
    put32(p, a->t1); p += 4;
    memcpy(p, a->hsig_u, AUTH_HSIG); p += AUTH_HSIG;
    p += cert_field_encode(p, &a->self_cert, full || a->full_certs);
    memcpy(p, a->c_sg, AUTH_KEM_CT); p += AUTH_KEM_CT;
    memcpy(p, a->epk_s, AUTH_KEM_PK); p += AUTH_KEM_PK;
    memcpy(p, a->e_su, AUTH_KEM_CT); p += AUTH_KEM_CT;
    memcpy(p, a->mu_s, AUTH_NONCE); p += AUTH_NONCE;
    put32(p, a->t2); p += 4;
    memcpy(p, a->hsig_s, AUTH_HSIG); p += AUTH_HSIG;
    return (int)(p - out);
}

static int build_msg4(Auth_Sat_t *a, uint8_t *out, bool full)
{
    uint8_t *p = out;
    uint8_t  h[32];
    p[0] = SAT_AUTH_VERSION;
    p[1] = AUTH_MSG4;
    p += 2;
    p += cert_field_encode(p, &a->self_cert, full || a->full_certs);
    pqsat_sha3_256(h, a->c_sg, AUTH_KEM_CT);
    memcpy(p, h, 32); p += 32;
    pqsat_sha3_256(h, a->epk_s, AUTH_KEM_PK); /* the user needs only the hash of our ephemeral key */
    memcpy(p, h, 32); p += 32;
    memcpy(p, a->e_su, AUTH_KEM_CT); p += AUTH_KEM_CT;
    memcpy(p, a->mu_s, AUTH_NONCE); p += AUTH_NONCE;
    put32(p, a->t2); p += 4;
    memcpy(p, a->hsig_s, AUTH_HSIG); p += AUTH_HSIG;
    /* the ground station's contribution, with its certificate in full if demanded */
    p += cert_field_encode(p, &a->gs_cert, full || a->gs_cert_full);
    memcpy(p, a->c_gu, AUTH_KEM_CT); p += AUTH_KEM_CT;
    pqsat_sha3_256(h, a->e_gs, AUTH_KEM_CT); /* e_gs is ours; the user needs only its hash */
    memcpy(p, h, 32); p += 32;
    memcpy(p, a->e_gu, AUTH_KEM_CT); p += AUTH_KEM_CT;
    memcpy(p, a->mu_g, AUTH_NONCE); p += AUTH_NONCE;
    put32(p, a->t3); p += 4;
    memcpy(p, a->hsig_g, AUTH_HSIG); p += AUTH_HSIG;
    return (int)(p - out);
}

static void send_demand(Auth_Sat_t *a, uint16_t to)
{
    uint8_t d[3] = {SAT_AUTH_VERSION, AUTH_DEMAND, 0x01};
    a->demands_sent++;
    a->send(to, d, 3, a->ctx);
}

/* A certificate received in band stays only if its handshake completes. */
static void drop_candidates(Auth_Sat_t *a)
{
#ifdef AUTH_NO_CERT_PIN
    (void)a;
#else
    if (a->gs_cert.valid && a->gs_cert.candidate)
    {
        a->gs_cert.valid = false;
        say(a, "auth: candidate certificate of the ground station dropped", NULL);
    }
    if (a->ue_cert.valid && a->ue_cert.candidate)
    {
        a->ue_cert.valid = false;
        say(a, "auth: candidate certificate of the user dropped", NULL);
    }
#endif
}

static void fail(Auth_Sat_t *a, const char *why)
{
    say(a, "auth: handshake failed: %s", why);
    a->handshakes_failed++;
    a->state = AUTH_IDLE;
    a->have_sk = false;
    drop_candidates(a);
    erase_ephemeral(a);
}

/* A message that fails verification while a handshake is in progress is
 * dropped and the handshake keeps waiting for a good one, so a forged frame
 * cannot abort a live handshake.  Only the timeout abandons it. */
static void reject(Auth_Sat_t *a, const char *why)
{
    say(a, "auth: message rejected: %s", why);
    a->messages_rejected++;
}

static bool replayed(Auth_Sat_t *a, const uint8_t *mu, uint32_t now)
{
    unsigned i;

    for (i = 0; i < AUTH_REPLAY_CACHE; i++)
    {
        if (a->seen_valid[i] && now - a->seen_t[i] <= 2u * a->fresh_s && memcmp(a->seen_mu[i], mu, AUTH_NONCE) == 0)
        {
            return true;
        }
    }
    return false;
}

static void remember(Auth_Sat_t *a, const uint8_t *mu, uint32_t now)
{
    memcpy(a->seen_mu[a->seen_next], mu, AUTH_NONCE);
    a->seen_t[a->seen_next]     = now;
    a->seen_valid[a->seen_next] = true;
    a->seen_next                = (a->seen_next + 1) % AUTH_REPLAY_CACHE;
}

static bool fresh(const Auth_Sat_t *a, uint32_t ts, uint32_t now)
{
    uint32_t d = ts > now ? ts - now : now - ts;
    return d <= a->fresh_s;
}

void Auth_SetFresh(Auth_Sat_t *a, uint32_t seconds)
{
    a->fresh_s = seconds;
}

/* ---------------------------------------------------------------- handlers */

static void on_msg1_verify(Auth_Sat_t *a, uint16_t from, const uint8_t *m, int n, uint32_t now);

/* MSG1 is verified on a scratch copy of the state and committed only when it
 * is good, so an unverified MSG1 cannot disturb a handshake in progress. */
static void on_msg1(Auth_Sat_t *a, uint16_t from, const uint8_t *m, int n, uint32_t now)
{
    static Auth_Sat_t tmp;

    memcpy(&tmp, a, sizeof tmp);
    on_msg1_verify(&tmp, from, m, n, now);
    if (tmp.state == AUTH_SENT2)
    {
        memcpy(a, &tmp, sizeof tmp); /* accepted: new handshake replaces any previous one */
    }
    else
    {
        a->handshakes_failed = tmp.handshakes_failed; /* rejected: previous handshake untouched */
        a->replays_rejected  = tmp.replays_rejected;
        a->demands_sent      = tmp.demands_sent;
    }
}

static void on_msg1_verify(Auth_Sat_t *a, uint16_t from, const uint8_t *m, int n, uint32_t now)
{
    static uint8_t out[AUTH_MAX_MSG];
    const uint8_t *p = m + 2;
    const uint8_t *cpay;
    const double   b_kem = a->t_kem_us, b_sign = a->t_sign_us, b_verify = a->t_verify_us, b_cert = a->t_cert_us,
                   b_wrap = a->t_wrap_us;
    uint8_t        cmode, h[32];
    int            k, r;
    uint16_t       id_ue, id_sat, id_gs;
    double         t0;

    if (n < 2 + 6)
    {
        fail(a, "MSG1 too short");
        return;
    }
    id_ue  = get16(p); id_sat = get16(p + 2); id_gs = get16(p + 4);
    p += 6;
    if (id_sat != a->ident || id_gs != a->id_gs || id_ue != from)
    {
        fail(a, "MSG1 addressed to another satellite or ground station");
        return;
    }
    k = cert_field_decode(p, n - (int)(p - m), &cmode, &cpay);
    if (k < 0 || n - (int)(p - m) - k != AUTH_KEM_CT + AUTH_KEM_PK + AUTH_NONCE + 4 + AUTH_HSIG)
    {
        fail(a, "MSG1 malformed");
        return;
    }
    p += k;
    /* a new handshake replaces any stale one from the same user */
    a->state = AUTH_IDLE;
    a->have_sk = false;
    drop_candidates(a); /* a certificate received in band in an unfinished handshake does not outlive it */
    memcpy(a->c_us, p, AUTH_KEM_CT); p += AUTH_KEM_CT;
    memcpy(a->epk_u, p, AUTH_KEM_PK); p += AUTH_KEM_PK;
    memcpy(a->mu_u, p, AUTH_NONCE); p += AUTH_NONCE;
    a->t1 = get32(p); p += 4;
    memcpy(a->hsig_u, p, AUTH_HSIG);
    if (!fresh(a, a->t1, now))
    {
        fail(a, "stale timestamp");
        return;
    }
    if (replayed(a, a->mu_u, now))
    {
        a->replays_rejected++;
        fail(a, "replayed MSG1");
        return;
    }
    r = cert_resolve(a, &a->ue_cert, cmode, cpay, id_ue, AUTH_ROLE_UE, now);
    if (r == 0)
    {
        say(a, "auth: user certificate unknown, demanding full", NULL);
        send_demand(a, from);
        return;
    }
    if (r < 0)
    {
        fail(a, "user certificate rejected");
        return;
    }
    a->id_ue        = id_ue;
    a->ue_cert_full = (cmode == AUTH_CERT_MODE_FULL);
    a->started      = now;

    t0 = now_us();
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(a->ss_us, a->c_us, a->sk_kappa);
    a->t_kem_us += now_us() - t0;

    /* Π1 = ID_UE | ID_SAT | ID_GS | ω_UE | h(c_us) | h(epk_u) | μ_u | T1 */
    put16(a->pi1, id_ue); put16(a->pi1 + 2, a->ident); put16(a->pi1 + 4, a->id_gs);
    memcpy(a->pi1 + 6, a->ue_cert.omega, 32);
    pqsat_sha3_256(a->pi1 + 38, a->c_us, AUTH_KEM_CT);
    pqsat_sha3_256(a->pi1 + 70, a->epk_u, AUTH_KEM_PK);
    memcpy(a->pi1 + 102, a->mu_u, 32);
    put32(a->pi1 + 134, a->t1);
    pqsat_sha3_256(h, a->pi1, AUTH_PI1);
    if (!hybrid_verify(a, a->ue_cert.pk_sigma, a->ss_us, h, a->hsig_u, true))
    {
        fail(a, "user signature rejected");
        return;
    }
    if (!a->gs_cert.valid || a->gs_cert.role != AUTH_ROLE_GS)
    {
        fail(a, "no ground station certificate loaded");
        return;
    }

    /* our contribution */
    random_bytes(a->mu_s, AUTH_NONCE);
    a->t2 = now;
    t0    = now_us();
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(a->c_sg, a->ss_sg, a->gs_cert.pk_kappa);
    /* session secret k_su for the user under the user's ephemeral key (the signature just
     * verified binds that key), and our own ephemeral key pair for the ground station */
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(a->e_su, a->k_su, a->epk_u);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_keypair(a->epk_s, a->esk_s);
    a->t_kem_us += now_us() - t0;
    /* Π2 = Π1 | ID_SAT | ω_SAT | h(c_sg) | h(epk_s) | h(e_su) | μ_s | T2 */
    memcpy(a->pi2, a->pi1, AUTH_PI1);
    put16(a->pi2 + AUTH_PI1, a->ident);
    memcpy(a->pi2 + AUTH_PI1 + 2, a->self_cert.omega, 32);
    pqsat_sha3_256(a->pi2 + AUTH_PI1 + 34, a->c_sg, AUTH_KEM_CT);
    pqsat_sha3_256(a->pi2 + AUTH_PI1 + 66, a->epk_s, AUTH_KEM_PK);
    pqsat_sha3_256(a->pi2 + AUTH_PI1 + 98, a->e_su, AUTH_KEM_CT);
    memcpy(a->pi2 + AUTH_PI1 + 130, a->mu_s, 32);
    put32(a->pi2 + AUTH_PI1 + 162, a->t2);
    pqsat_sha3_256(h, a->pi2, AUTH_PI2);
    hybrid_sign(a, a->hsig_s, a->ss_sg, h);

    k        = build_msg2(a, out, false);
    remember(a, a->mu_u, now);
    a->t0_kem_us    = b_kem; /* per handshake baseline: everything from this MSG1 on */
    a->t0_sign_us   = b_sign;
    a->t0_verify_us = b_verify;
    a->t0_cert_us   = b_cert;
    a->t0_wrap_us   = b_wrap;
    a->state = AUTH_SENT2;
    say(a, "auth: user verified, MSG2 to ground", NULL);
    a->send(a->id_gs, out, k, a->ctx);
}

static void on_msg3(Auth_Sat_t *a, const uint8_t *m, int n, uint32_t now)
{
    static uint8_t out[AUTH_MAX_MSG];
    const uint8_t *p = m + 2;
    const uint8_t *cpay;
    uint8_t        cmode;
    int            k, r;

    k = cert_field_decode(p, n - 2, &cmode, &cpay);
    if (k < 0 || n - 2 - k != 3 * AUTH_KEM_CT + AUTH_NONCE + 4 + AUTH_HSIG)
    {
        reject(a, "MSG3 malformed");
        return;
    }
    p += k;
    memcpy(a->c_gu, p, AUTH_KEM_CT); p += AUTH_KEM_CT;
    memcpy(a->e_gs, p, AUTH_KEM_CT); p += AUTH_KEM_CT;
    memcpy(a->e_gu, p, AUTH_KEM_CT); p += AUTH_KEM_CT;
    memcpy(a->mu_g, p, AUTH_NONCE); p += AUTH_NONCE;
    a->t3 = get32(p); p += 4;
    memcpy(a->hsig_g, p, AUTH_HSIG);
    if (!fresh(a, a->t3, now))
    {
        reject(a, "stale timestamp in MSG3");
        return;
    }
    r = cert_resolve(a, &a->gs_cert, cmode, cpay, a->id_gs, AUTH_ROLE_GS, now);
    if (r == 0)
    {
        send_demand(a, a->id_gs);
        return;
    }
    if (r < 0)
    {
        reject(a, "ground station certificate rejected");
        return;
    }
    a->gs_cert_full = (cmode == AUTH_CERT_MODE_FULL);

    /* Π3 = Π2 | ID_GS | ω_GS | h(c_gu) | h(e_gs) | h(e_gu) | μ_g | T3 */
    memcpy(a->pi3, a->pi2, AUTH_PI2);
    put16(a->pi3 + AUTH_PI2, a->id_gs);
    memcpy(a->pi3 + AUTH_PI2 + 2, a->gs_cert.omega, 32);
    pqsat_sha3_256(a->pi3 + AUTH_PI2 + 34, a->c_gu, AUTH_KEM_CT);
    pqsat_sha3_256(a->pi3 + AUTH_PI2 + 66, a->e_gs, AUTH_KEM_CT);
    pqsat_sha3_256(a->pi3 + AUTH_PI2 + 98, a->e_gu, AUTH_KEM_CT);
    memcpy(a->pi3 + AUTH_PI2 + 130, a->mu_g, 32);
    put32(a->pi3 + AUTH_PI2 + 162, a->t3);
    pqsat_sha3_256(a->h_pi3, a->pi3, AUTH_PI3);
    /* ML-DSA half now; the KEM half is keyed by ss_gu which arrives in MSG7 */
    if (!hybrid_verify(a, a->gs_cert.pk_sigma, NULL, a->h_pi3, a->hsig_g, false))
    {
        reject(a, "ground station signature rejected");
        return;
    }
    /* k_gs comes to us under our ephemeral key.  The wrap key takes it and ss_sg, and the wrap
     * carries the two secrets the ground station lacks, k_su and ss_us */
    {
        double tk = now_us();
        PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(a->k_gs, a->e_gs, a->esk_s);
        a->t_kem_us += now_us() - tk;
    }
    {
        uint8_t kb[2 * AUTH_SS];
        memcpy(kb, a->k_gs, AUTH_SS);
        memcpy(kb + AUTH_SS, a->ss_sg, AUTH_SS);
        pqsat_kdf(a->w_sg, kb, sizeof kb, "wrap-sg");
        memset(kb, 0, sizeof kb);
    }
    do_wrap(a, a->c_su_g, a->w_sg, "wrap-su-g", a->k_su, a->ss_us);
    k        = build_msg4(a, out, false);
    a->state = AUTH_SENT4;
    say(a, "auth: ground verified, MSG4 to user", NULL);
    a->send(a->id_ue, out, k, a->ctx);
}

static void on_msg5(Auth_Sat_t *a, const uint8_t *m, int n)
{
    uint8_t out[2 + AUTH_WRAP + AUTH_TAG];
    if (n != 2 + AUTH_TAG)
    {
        reject(a, "MSG5 malformed");
        return;
    }
    out[0] = SAT_AUTH_VERSION;
    out[1] = AUTH_MSG6;
    memcpy(out + 2, a->c_su_g, AUTH_WRAP);
    memcpy(out + 2 + AUTH_WRAP, m + 2, AUTH_TAG);
    a->state = AUTH_SENT6;
    a->send(a->id_gs, out, sizeof out, a->ctx);
}

static void on_msg7(Auth_Sat_t *a, const uint8_t *m, int n)
{
    uint8_t out[2 + AUTH_WRAP + 2 * AUTH_TAG];
    uint8_t tag[32];
    /* MSG7 = C_gs->u | C_gu->s | tag_g ; the first wrap is for the user */
    const uint8_t *for_user = m + 2, *c_gu_s = m + 2 + AUTH_WRAP, *tag_g = m + 2 + 2 * AUTH_WRAP;
    if (n != 2 + 2 * AUTH_WRAP + AUTH_TAG)
    {
        reject(a, "MSG7 malformed");
        return;
    }
    if (!do_unwrap(a, a->k_gu, a->ss_gu, a->w_sg, "wrap-gu-s", c_gu_s))
    {
        reject(a, "wrap from ground station rejected");
        return;
    }
    if (!verify_kem_half(a->ss_gu, a->h_pi3, a->hsig_g))
    {
        reject(a, "ground station KEM half rejected");
        return;
    }
    derive_sk(a);
    tag_of(tag, a->sk, AUTH_SS, NULL, 0, a, "GS-fin");
    if (memcmp(tag, tag_g, AUTH_TAG) != 0)
    {
        memset(a->sk, 0, sizeof a->sk);
        reject(a, "ground station confirmation tag rejected");
        return;
    }
    a->have_sk = true;
    /* our own confirmation of SK: to the user now, to the ground station with MSG8 */
    tag_of(a->tag_s, a->sk, AUTH_SS, NULL, 0, a, "SAT-fin");
    out[0] = SAT_AUTH_VERSION;
    out[1] = AUTH_MSG7_FWD;
    memcpy(out + 2, for_user, AUTH_WRAP);
    memcpy(out + 2 + AUTH_WRAP, tag_g, AUTH_TAG);
    memcpy(out + 2 + AUTH_WRAP + AUTH_TAG, a->tag_s, AUTH_TAG);
    erase_ephemeral(a); /* SK is confirmed: nothing that produced it is kept */
    a->state = AUTH_SENT7;
    a->send(a->id_ue, out, sizeof out, a->ctx);
}

static void on_msg8(Auth_Sat_t *a, const uint8_t *m, int n)
{
    uint8_t tag[32], out[2 + 2 * AUTH_TAG];
    char    hex[80];
    int     i;
    if (n != 2 + AUTH_TAG)
    {
        reject(a, "MSG8 malformed");
        return;
    }
    tag_of(tag, a->sk, AUTH_SS, NULL, 0, a, "UE-fin-final");
    if (memcmp(tag, m + 2, AUTH_TAG) != 0)
    {
        reject(a, "user final confirmation rejected");
        return;
    }
    a->state = AUTH_DONE;
    a->handshakes_ok++;
    a->gs_cert.candidate = false; /* verified in a completed handshake: cached from now on */
    a->ue_cert.candidate = false;
    for (i = 0; i < 16; i++)
    {
        snprintf(hex + 2 * i, 3, "%02x", a->sk[i]);
    }
    say(a, "auth: handshake complete, SK %s...", hex);
    {
        char t[160];

        snprintf(t, sizeof t, "auth: satellite crypto this handshake, us: kem %.0f sign %.0f verify %.0f cert %.0f wrap %.0f",
                 a->t_kem_us - a->t0_kem_us, a->t_sign_us - a->t0_sign_us, a->t_verify_us - a->t0_verify_us,
                 a->t_cert_us - a->t0_cert_us, a->t_wrap_us - a->t0_wrap_us);
        say(a, "%s", t);
    }
    /* forwarded to the ground station together with our own confirmation of SK */
    out[0] = SAT_AUTH_VERSION;
    out[1] = AUTH_MSG8_FWD;
    memcpy(out + 2, m + 2, AUTH_TAG);
    memcpy(out + 2 + AUTH_TAG, a->tag_s, AUTH_TAG);
    a->send(a->id_gs, out, sizeof out, a->ctx);
    if (a->onSession)
    {
        a->onSession(a->sk, a->ctx); /* SDLS: key the link from the confirmed session key */
    }
}

void Auth_SetSessionHook(Auth_Sat_t *a, Auth_SessionFn fn)
{
    a->onSession = fn;
}

void Auth_OnMessage(Auth_Sat_t *a, uint16_t from, const uint8_t *msg, int len, uint32_t now_s)
{
    static uint8_t out[AUTH_MAX_MSG];
    uint8_t t;
    int     k;

    if (len < 2 || msg[0] != SAT_AUTH_VERSION)
    {
        say(a, "auth: bad version", NULL);
        return;
    }
    t = msg[1];
    if (t == AUTH_CRL)
    {
        /* accepted from any sender: the authority's signature is what counts */
        (void)Auth_InstallCrl(a, msg, len);
    }
    else if (t == AUTH_MSG1 && from != a->id_gs)
    {
        on_msg1(a, from, msg, len, now_s);
    }
    else if (t == AUTH_MSG3 && from == a->id_gs && a->state == AUTH_SENT2)
    {
        on_msg3(a, msg, len, now_s);
    }
    else if (t == AUTH_MSG5 && from == a->id_ue && a->state == AUTH_SENT4)
    {
        on_msg5(a, msg, len);
    }
    else if (t == AUTH_MSG7 && from == a->id_gs && a->state == AUTH_SENT6)
    {
        on_msg7(a, msg, len);
    }
    else if (t == AUTH_MSG8 && from == a->id_ue && a->state == AUTH_SENT7)
    {
        on_msg8(a, msg, len);
    }
    else if (t == AUTH_DEMAND && from == a->id_gs && a->state == AUTH_SENT2)
    {
        say(a, "auth: ground demands full certificates, resending MSG2", NULL);
        k = build_msg2(a, out, true);
        a->send(a->id_gs, out, k, a->ctx);
    }
    else if (t == AUTH_DEMAND && from == a->id_ue && a->state == AUTH_SENT4)
    {
        say(a, "auth: user demands full certificates, resending MSG4", NULL);
        k = build_msg4(a, out, true);
        a->send(a->id_ue, out, k, a->ctx);
    }
    else
    {
        say(a, "auth: unexpected message for current state, ignored", NULL);
    }
}

void Auth_Tick(Auth_Sat_t *a, uint32_t now_s)
{
    if (a->state != AUTH_IDLE && a->state != AUTH_DONE && now_s - a->started > AUTH_TIMEOUT_S)
    {
        fail(a, "timed out");
    }
}

/* ---------------------------------------------------------------- provisioning */

void Auth_Init(Auth_Sat_t *a, Auth_SendFn send, Auth_LogFn log, void *ctx)
{
    memset(a, 0, sizeof *a);
    a->send       = send;
    a->log        = log;
    a->ctx        = ctx;
    a->full_certs = true;
    a->fresh_s    = AUTH_FRESH_S;
}

/* Bundle file layout, written by enrol.py:
 *   ident 2 | id_gs 2 | sk_sigma 4032 | sk_kappa 2400 | ta_pk_sigma 1952 | own certificate bundle 7608
 */
int Auth_LoadBundle(Auth_Sat_t *a, const char *path)
{
    static uint8_t buf[2 + 2 + AUTH_DSA_SK + AUTH_KEM_SK + AUTH_DSA_PK + AUTH_CERT_BUNDLE];
    FILE *f = fopen(path, "rb");
    size_t n;
    const uint8_t *p = buf;
    if (!f)
    {
        return -1;
    }
    n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n != sizeof buf)
    {
        return -2;
    }
    a->ident = get16(p); p += 2;
    a->id_gs = get16(p); p += 2;
    memcpy(a->sk_sigma, p, AUTH_DSA_SK); p += AUTH_DSA_SK;
    memcpy(a->sk_kappa, p, AUTH_KEM_SK); p += AUTH_KEM_SK;
    memcpy(a->ta_pk_sigma, p, AUTH_DSA_PK); p += AUTH_DSA_PK;
    cert_parse(&a->self_cert, p);
    if (!cert_verify_self(a, (uint32_t)time(NULL)))
    {
        return -3;
    }
    if (a->self_cert.role != AUTH_ROLE_SAT)
    {
        return -4; /* this node runs the satellite role: its certificate must say so */
    }
    return 0;
}

static int load_cert_into(Auth_Sat_t *a, Auth_Cert_t *slot, const char *path, uint8_t role)
{
    static uint8_t buf[AUTH_CERT_BUNDLE];
    FILE *f = fopen(path, "rb");
    size_t n;
    if (!f)
    {
        return -1;
    }
    n = fread(buf, 1, sizeof buf, f);
    fclose(f);
    if (n != sizeof buf)
    {
        return -2;
    }
    cert_parse(slot, buf);
    if (!cert_verify_peer(a, slot, (uint32_t)time(NULL)))
    {
        return -3;
    }
    if (slot->role != role)
    {
        slot->valid = false;
        return -4;
    }
    slot->installed = true;  /* provisioned: the trusted binding of this identity */
    slot->candidate = false;
    return 0;
}

int Auth_LoadPeerCert(Auth_Sat_t *a, const char *path)
{
    return load_cert_into(a, &a->gs_cert, path, AUTH_ROLE_GS);
}

int Auth_LoadUserCert(Auth_Sat_t *a, const char *path)
{
    return load_cert_into(a, &a->ue_cert, path, AUTH_ROLE_UE);
}

/* ---------------------------------------------------------------- constellation phase */

void Auth_GroundLinkKey(uint8_t out[32], const uint8_t sk[32])
{
    pqsat_kdf(out, sk, AUTH_SS, "ground-link");
}

void Auth_OrderKey(uint8_t out[32], const uint8_t sk[32])
{
    pqsat_kdf(out, sk, AUTH_SS, "order");
}

void Auth_NextLinkKey(uint8_t out[32], const uint8_t sk[32], uint16_t id_next)
{
    uint8_t b[AUTH_SS + 2];
    memcpy(b, sk, AUTH_SS);
    put16(b + AUTH_SS, id_next);
    pqsat_kdf(out, b, sizeof b, "next-link");
    memset(b, 0, sizeof b);
}

void Auth_OrderMac(uint8_t out[32], const uint8_t k_ord[32], uint16_t user, uint16_t serving, uint16_t target)
{
    uint8_t m[8 + 6];
    memcpy(m, "HANDOVER", 8);
    put16(m + 8, user);
    put16(m + 10, serving);
    put16(m + 12, target);
    pqsat_hmac_sha3_256(out, k_ord, 32, m, sizeof m);
}

int Auth_LoadSatCert(Auth_Sat_t *a, Auth_Peers_t *peers, const char *path)
{
    int r;
    if (peers->n >= AUTH_PEERS_MAX)
    {
        return -5;
    }
    r = load_cert_into(a, &peers->cert[peers->n], path, AUTH_ROLE_SAT);
    if (r == 0)
    {
        peers->n++;
    }
    return r;
}

static const Auth_Cert_t *peer_cert(const Auth_Peers_t *peers, uint16_t ident)
{
    int i;
    for (i = 0; peers != NULL && i < peers->n; i++)
    {
        if (peers->cert[i].valid && peers->cert[i].ident == ident && peers->cert[i].role == AUTH_ROLE_SAT)
        {
            return &peers->cert[i];
        }
    }
    return NULL;
}

static void xfer_digest(uint8_t out[32], const uint8_t *pkt)
{
    pqsat_sha3_256(out, pkt, AUTH_XFER_HDR + AUTH_KEM_CT + AUTH_SS + 16);
}

int Auth_XferBuild(Auth_Sat_t *a, const Auth_Peers_t *peers, uint8_t label, uint16_t dst, uint16_t user,
                   const uint8_t key[32], uint32_t now_s, uint8_t *out)
{
    const Auth_Cert_t *c = peer_cert(peers, dst);
    uint8_t            ss[AUTH_SS], k[32], h[32], nonce[12];
    uint8_t           *ct = out + AUTH_XFER_HDR, *w = ct + AUTH_KEM_CT, *sig = w + AUTH_SS + 16;
    size_t             siglen = 0;

    if (c == NULL || Auth_IsRevoked(a, dst))
    {
        return -1;
    }
    out[0] = label;
    put16(out + 1, a->ident);
    put16(out + 3, dst);
    put16(out + 5, user);
    put32(out + 7, now_s);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_enc(ct, ss, c->pk_kappa);
    pqsat_kdf(k, ss, AUTH_SS, "xfer");
    pqsat_sha3_256(h, ct, AUTH_KEM_CT);
    memcpy(nonce, h, 12);
    pqsat_aes256gcm_encrypt(w, w + AUTH_SS, k, nonce, out, AUTH_XFER_HDR, key, AUTH_SS);
    xfer_digest(h, out);
    PQCLEAN_MLDSA65_CLEAN_crypto_sign_signature(sig, &siglen, h, 32, a->sk_sigma);
    memset(ss, 0, sizeof ss);
    memset(k, 0, sizeof k);
    return AUTH_XFER_LEN;
}

int Auth_XferOpen(Auth_Sat_t *a, const Auth_Peers_t *peers, const uint8_t *in, int len, uint8_t label,
                  uint32_t now_s, uint16_t *src, uint16_t *user, uint8_t key[32])
{
    const Auth_Cert_t *c;
    const uint8_t     *ct = in + AUTH_XFER_HDR, *w = ct + AUTH_KEM_CT, *sig = w + AUTH_SS + 16;
    uint8_t            ss[AUTH_SS], k[32], h[32], hx[32], nonce[12];
    uint32_t           t;
    int                r;

    if (len != AUTH_XFER_LEN || in[0] != label || get16(in + 3) != a->ident)
    {
        return -1;
    }
    *src  = get16(in + 1);
    *user = get16(in + 5);
    t     = get32(in + 7);
    c     = peer_cert(peers, *src);
    if (c == NULL || Auth_IsRevoked(a, *src))
    {
        return -2; /* the sender must hold a certificate with the satellite role */
    }
    xfer_digest(h, in);
    if (PQCLEAN_MLDSA65_CLEAN_crypto_sign_verify(sig, AUTH_DSA_SIG, h, 32, c->pk_sigma) != 0)
    {
        return -3;
    }
    if (!fresh(a, t, now_s))
    {
        return -4; /* a recorded transfer replayed later */
    }
    {
        /* The same transfer accepted a second time would key the link again with the same key
         * and restart its counters.  The ISL anti replay check stops that on a sound link; this
         * cache stops it when a relay or a holder of one ISL key sends the transfer again. */
        int i;
        for (i = 0; i < AUTH_XFER_SEEN; i++)
        {
            if (a->xfer_seen_t[i] != 0 && memcmp(a->xfer_seen[i], h, 32) == 0)
            {
                return -6;
            }
        }
    }
    memcpy(hx, h, 32);
    PQCLEAN_MLKEM768_CLEAN_crypto_kem_dec(ss, ct, a->sk_kappa);
    pqsat_kdf(k, ss, AUTH_SS, "xfer");
    pqsat_sha3_256(h, ct, AUTH_KEM_CT);
    memcpy(nonce, h, 12);
    r = pqsat_aes256gcm_decrypt(key, k, nonce, in, AUTH_XFER_HDR, w, AUTH_SS, w + AUTH_SS);
    memset(ss, 0, sizeof ss);
    memset(k, 0, sizeof k);
    if (r == 0)
    {
        int slot = a->xfer_seen_n++ % AUTH_XFER_SEEN;
        memcpy(a->xfer_seen[slot], hx, 32);
        a->xfer_seen_t[slot] = t == 0 ? 1u : t;
    }
    return r == 0 ? 0 : -5;
}

int Auth_LoadSatCerts(Auth_Sat_t *a, Auth_Peers_t *peers, const char *dir)
{
    char path[300];
    int  i;
    for (i = 1; i <= AUTH_PEERS_MAX; i++)
    {
        snprintf(path, sizeof path, "%s/sat%d.cert", dir, i);
        (void)Auth_LoadSatCert(a, peers, path);
    }
    return peers->n;
}

int Auth_XferBuildHook(void *ctx, uint8_t label, uint16_t dst, uint16_t user, const uint8_t key[32], uint32_t now_s,
                       uint8_t *out)
{
    Auth_XferCtx_t *x = (Auth_XferCtx_t *)ctx;
    return Auth_XferBuild(x->auth, x->peers, label, dst, user, key, now_s, out);
}

int Auth_XferOpenHook(void *ctx, const uint8_t *in, int len, uint8_t label, uint32_t now_s, uint16_t *src,
                      uint16_t *user, uint8_t key[32])
{
    Auth_XferCtx_t *x = (Auth_XferCtx_t *)ctx;
    return Auth_XferOpen(x->auth, x->peers, in, len, label, now_s, src, user, key);
}
