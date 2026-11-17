/* sat_auth.h  -  Phase 5 three party post quantum authentication, satellite role.
 *
 * Protocol: PROTOCOL.md.  This file is the C counterpart
 * of pqsat_roles.SatelliteSession and is checked against it octet for octet.
 *
 * Transport: space packets with APID SAT_AUTH_APID whose data field is
 *   src identity (2) | dst identity (2) | protocol message
 * Uplink arrives on the sender's TC virtual channel.  Downlink goes out on the
 * relay TM virtual channel and the dst field tells the terminals which of them
 * the message is for.
 */
#ifndef SAT_AUTH_H
#define SAT_AUTH_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SAT_AUTH_APID 700u
#define SAT_AUTH_VERSION 0x03u /* SK from session secrets and authentication secrets, tag_s, roles */

/* message types */
#define AUTH_MSG1 0x01u
#define AUTH_MSG2 0x02u
#define AUTH_MSG3 0x03u
#define AUTH_MSG4 0x04u
#define AUTH_MSG5 0x05u
#define AUTH_MSG6 0x06u
#define AUTH_MSG7 0x07u
#define AUTH_MSG7_FWD 0x08u
#define AUTH_MSG8 0x09u
#define AUTH_CRL 0x0Au /* revocation list signed by the trusted authority: issued 4 | count 2 | identities 2 each | ML-DSA-65 signature */
#define AUTH_MSG8_FWD 0x0Bu /* MSG8 as forwarded to the ground station: tag_u' | tag_s */
#define AUTH_REVOKED_MAX 64u

/* certificate roles: every node checks the role of a certificate before it uses it */
#define AUTH_ROLE_UE 0x01u
#define AUTH_ROLE_SAT 0x02u
#define AUTH_ROLE_GS 0x03u
#define AUTH_DEMAND 0x7Fu

/* primitive sizes, FIPS 204 and 203 */
#define AUTH_DSA_PK 1952
#define AUTH_DSA_SK 4032
#define AUTH_DSA_SIG 3309
#define AUTH_KEM_PK 1184
#define AUTH_KEM_SK 2400
#define AUTH_KEM_CT 1088
#define AUTH_SS 32

#define AUTH_ID 2
#define AUTH_ROLE 1
#define AUTH_NONCE 32
#define AUTH_TS 4
#define AUTH_HASH 32
#define AUTH_TAG 32
#define AUTH_HSIG (AUTH_DSA_SIG + AUTH_TAG)                                 /* 3341 */
#define AUTH_CERT_BODY (AUTH_ID + AUTH_ROLE + AUTH_DSA_PK + AUTH_KEM_PK + AUTH_HASH + 2 * AUTH_TS) /* 3179 */
#define AUTH_CERT_SIG (AUTH_KEM_CT + AUTH_DSA_SIG + AUTH_TAG)              /* 4429 */
#define AUTH_CERT_BUNDLE (AUTH_CERT_BODY + AUTH_CERT_SIG)                  /* 7608 */
#define AUTH_CERT_REF (AUTH_ID + AUTH_HASH)                                /* 34 */
#define AUTH_WRAP 80 /* one session secret and one authentication secret, 64 octets, and the 16 octet tag */
#define AUTH_PI1 138 /* 106 + h(epk_u) */
#define AUTH_PI2 304 /* Pi1 + 102 + h(epk_s) + h(e_su) */
#define AUTH_PI3 470 /* Pi2 + 102 + h(e_gs) + h(e_gu) */
#define AUTH_MAX_MSG 32768
#define AUTH_REPLAY_CACHE 16u
#define AUTH_FRESH_S 900u /* default freshness window; see Auth_SetFresh */
#define AUTH_TIMEOUT_S 1800u /* whole handshake; four large messages at 10 percent loss take about 900 s */

#define AUTH_CERT_MODE_REF 0x00u
#define AUTH_CERT_MODE_FULL 0x01u

#define AUTH_XFER_SEEN 16 /* transfers remembered against replay inside the freshness window */

typedef struct
{
    bool     valid;
    uint16_t ident;
    uint8_t  role;
    uint8_t  pk_sigma[AUTH_DSA_PK];
    uint8_t  pk_kappa[AUTH_KEM_PK];
    uint8_t  omega[AUTH_HASH];
    uint32_t not_before, not_after;
    uint8_t  bundle[AUTH_CERT_BUNDLE]; /* kept so it can be re-sent in full mode */
    uint8_t  digest[AUTH_HASH];        /* h(body) */
    bool     installed;                /* provisioned at enrollment: never replaced by a certificate received in band */
    bool     candidate;                /* received in band in the handshake in progress, dropped if it fails */
} Auth_Cert_t;

/* Send one protocol message to a terminal.  The transport adds the APID and
 * the src/dst prefix. */
typedef void (*Auth_SendFn)(uint16_t dst, const uint8_t *msg, int len, void *ctx);
typedef void (*Auth_LogFn)(const char *msg, void *ctx);
/* Called once a handshake has completed and the session key is confirmed. */
typedef void (*Auth_SessionFn)(const uint8_t sk[32], void *ctx);

typedef enum
{
    AUTH_IDLE = 0,
    AUTH_SENT2,
    AUTH_SENT4,
    AUTH_SENT6,
    AUTH_SENT7,
    AUTH_DONE
} Auth_State_t;

typedef struct
{
    /* provisioned at enrollment */
    uint16_t    ident;
    uint16_t    id_gs;
    uint8_t     sk_sigma[AUTH_DSA_SK];
    uint8_t     sk_kappa[AUTH_KEM_SK];
    uint8_t     ta_pk_sigma[AUTH_DSA_PK];
    Auth_Cert_t self_cert;
    bool        full_certs; /* send our certificate in full (true) or by reference */

    /* certificate cache: ground station plus the user in progress */
    Auth_Cert_t gs_cert;
    Auth_Cert_t ue_cert;
    uint32_t    cert_pin_rejected; /* certificates received in band that differed from the installed one */

    /* handshake in progress */
    Auth_State_t state;
    uint32_t     started;
    uint32_t     fresh_s;   /* freshness window, seconds */
    uint16_t     id_ue;
    bool         ue_cert_full;   /* how the user sent its certificate */
    bool         gs_cert_full;   /* how the ground station sent its certificate in MSG3 */
    uint8_t      mu_u[AUTH_NONCE], mu_s[AUTH_NONCE], mu_g[AUTH_NONCE];
    uint32_t     t1, t2, t3;
    uint8_t      c_us[AUTH_KEM_CT], c_sg[AUTH_KEM_CT], c_gu[AUTH_KEM_CT];
    uint8_t      ss_us[AUTH_SS], ss_sg[AUTH_SS], ss_gu[AUTH_SS];
    uint8_t      hsig_u[AUTH_HSIG], hsig_s[AUTH_HSIG], hsig_g[AUTH_HSIG];
    uint8_t      pi1[AUTH_PI1], pi2[AUTH_PI2], pi3[AUTH_PI3];
    uint8_t      h_pi3[AUTH_HASH];
    /* ephemeral material: erased when the session key is confirmed or the handshake ends */
    uint8_t      epk_u[AUTH_KEM_PK];                   /* user's ephemeral key, from MSG1 */
    uint8_t      epk_s[AUTH_KEM_PK], esk_s[AUTH_KEM_SK]; /* our ephemeral key pair */
    uint8_t      e_su[AUTH_KEM_CT], e_gs[AUTH_KEM_CT], e_gu[AUTH_KEM_CT];
    uint8_t      k_su[AUTH_SS], k_gs[AUTH_SS], k_gu[AUTH_SS]; /* session secrets; SK takes them and ss_us, ss_sg, ss_gu */
    uint8_t      w_sg[AUTH_SS];                        /* wrap key KDF(k_gs | ss_sg) shared with the ground station */
    uint8_t      c_su_g[AUTH_WRAP];                    /* k_su | ss_us for the ground station under w_sg */
    uint8_t      tag_s[AUTH_TAG];                      /* our confirmation of SK, sent in MSG7f and with MSG8 */
    uint8_t      sk[AUTH_SS];
    bool         have_sk;

    /* revocation list: identities the trusted authority has revoked.  A certificate of a
     * revoked identity is rejected in full and in reference form. */
    uint16_t revoked[AUTH_REVOKED_MAX];
    unsigned n_revoked;
    uint32_t crl_issued;       /* issue time of the installed list; an older list is refused */
    uint32_t revoked_rejected; /* messages rejected for a revoked identity */
    char     crl_path[128];    /* when set, an accepted list is stored here */

    /* counters and timing, reported for the paper */
    uint32_t handshakes_ok, handshakes_failed, demands_sent;
    uint32_t messages_rejected, replays_rejected;

    /* replay cache: user nonces of MSG1s accepted inside the freshness window */
    uint8_t  seen_mu[AUTH_REPLAY_CACHE][AUTH_NONCE];
    uint32_t seen_t[AUTH_REPLAY_CACHE];
    bool     seen_valid[AUTH_REPLAY_CACHE];
    unsigned seen_next;
    double   t_kem_us, t_sign_us, t_verify_us, t_cert_us, t_wrap_us;          /* cumulative */
    double   t0_kem_us, t0_sign_us, t0_verify_us, t0_cert_us, t0_wrap_us;     /* at start of current handshake */

    Auth_SendFn send;

    Auth_SessionFn onSession; /* optional */
    Auth_LogFn  log;
    void       *ctx;
    /* end to end key transfers accepted inside the freshness window: one accepted twice is a replay */
    uint8_t  xfer_seen[AUTH_XFER_SEEN][32];
    uint32_t xfer_seen_t[AUTH_XFER_SEEN];
    int      xfer_seen_n;
} Auth_Sat_t;

/* Load the provisioned bundle produced by the enrollment tool.  Returns 0 on success. */
int Auth_LoadBundle(Auth_Sat_t *a, const char *path);
/* Load a peer certificate bundle into the cache: the ground station's, or a
 * user's that the satellite is provisioned to know in advance. */
int Auth_LoadPeerCert(Auth_Sat_t *a, const char *path);
int Auth_LoadUserCert(Auth_Sat_t *a, const char *path);

void Auth_Init(Auth_Sat_t *a, Auth_SendFn send, Auth_LogFn log, void *ctx);

/* Revocation.  Auth_InstallCrl verifies the trusted authority's signature on a revocation
 * list message (type AUTH_CRL) and installs it when it is newer than the one held; returns
 * the number of revoked identities or -1.  Auth_LoadCrl reads the same message from a file. */
int  Auth_InstallCrl(Auth_Sat_t *a, const uint8_t *msg, int len);
int  Auth_LoadCrl(Auth_Sat_t *a, const char *path);
bool Auth_IsRevoked(const Auth_Sat_t *a, uint16_t ident);

/* ---- Constellation phase (PROTOCOL.md, C6 to C9) ----
 * SK never leaves the serving satellite.  Three keys are derived from it:
 *   K_gl  = KDF(SK, "ground-link")            for the feeder satellite, keys the ground station link
 *   K_ord = KDF(SK, "order")                  authenticates hand over orders for this user
 *   SK_n  = KDF(SK | ID_n, "next-link")       user link key after hand over to satellite n
 * A key that travels between satellites goes end to end in a transfer packet:
 *   label 1 | src 2 | dst 2 | user 2 | time 4 | c 1088 | AES-256-GCM(KDF(ss,"xfer"), key) 48 | ML-DSA-65 signature 3309
 * with (c, ss) = ML-KEM.Encaps(pk of dst from its certificate).  The header is the associated
 * data of the wrap and the signature covers header, c and wrap.  A relay cannot open it. */
#define AUTH_XFER_GLINK 0x01u
#define AUTH_XFER_USERSESS 0x02u
#define AUTH_XFER_HDR 11
#define AUTH_XFER_LEN (AUTH_XFER_HDR + AUTH_KEM_CT + AUTH_SS + 16 + AUTH_DSA_SIG) /* 4456 */
#define AUTH_PEERS_MAX 8

/* certificates of the other satellites of the constellation, loaded at provisioning */
typedef struct
{
    Auth_Cert_t cert[AUTH_PEERS_MAX];
    int         n;
} Auth_Peers_t;

/* Load NAME.cert of another satellite; the authority's signature and the satellite role are checked. */
int Auth_LoadSatCert(Auth_Sat_t *a, Auth_Peers_t *peers, const char *path);

/* Load sat1.cert to sat8.cert from the provisioning directory, whichever exist.  Returns the number loaded. */
int Auth_LoadSatCerts(Auth_Sat_t *a, Auth_Peers_t *peers, const char *dir);

/* Adapters with the signature the satellite core expects (Sat_XferBuildFn, Sat_XferOpenFn). */
typedef struct
{
    Auth_Sat_t   *auth;
    Auth_Peers_t *peers;
} Auth_XferCtx_t;
int Auth_XferBuildHook(void *ctx, uint8_t label, uint16_t dst, uint16_t user, const uint8_t key[32], uint32_t now_s,
                       uint8_t *out);
int Auth_XferOpenHook(void *ctx, const uint8_t *in, int len, uint8_t label, uint32_t now_s, uint16_t *src,
                      uint16_t *user, uint8_t key[32]);

void Auth_GroundLinkKey(uint8_t out[32], const uint8_t sk[32]);
void Auth_OrderKey(uint8_t out[32], const uint8_t sk[32]);
void Auth_NextLinkKey(uint8_t out[32], const uint8_t sk[32], uint16_t id_next);
/* MAC of a hand over order: HMAC(K_ord, "HANDOVER" | user | serving | target) */
void Auth_OrderMac(uint8_t out[32], const uint8_t k_ord[32], uint16_t user, uint16_t serving, uint16_t target);

/* Build a transfer of `key` to satellite dst.  Returns AUTH_XFER_LEN, or -1 when no certificate of dst is held. */
int Auth_XferBuild(Auth_Sat_t *a, const Auth_Peers_t *peers, uint8_t label, uint16_t dst, uint16_t user,
                   const uint8_t key[32], uint32_t now_s, uint8_t *out);
/* Open a transfer addressed to this satellite.  Returns 0 and fills src, user and key, or a negative
 * value: -1 malformed or not for us, -2 sender unknown or not a satellite, -3 signature, -4 stale, -5 wrap,
 * -6 the same transfer was accepted before (replay inside the freshness window). */
int Auth_XferOpen(Auth_Sat_t *a, const Auth_Peers_t *peers, const uint8_t *in, int len, uint8_t label,
                  uint32_t now_s, uint16_t *src, uint16_t *user, uint8_t key[32]);

/* A protocol message arrived from `from` (identity in the packet prefix). */
void Auth_OnMessage(Auth_Sat_t *a, uint16_t from, const uint8_t *msg, int len, uint32_t now_s);

/* Abandon a stalled handshake. */
void Auth_Tick(Auth_Sat_t *a, uint32_t now_s);

/* Override the freshness window (seconds).  The window must cover clock skew
   plus the worst case transfer time of the message path up to the check. */
void Auth_SetFresh(Auth_Sat_t *a, uint32_t seconds);
void Auth_SetSessionHook(Auth_Sat_t *a, Auth_SessionFn fn);

#ifdef __cplusplus
}
#endif
#endif
