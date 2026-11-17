/*
 * SAT-1 SDLS wrapper over NASA CryptoLib.  See sat_sdls.h.
 */
#include <stdlib.h>
#include <string.h>

#include "crypto.h"
#include "crypto_error.h"
#include "key_interface.h"
#include "sa_interface.h"
#include "pqsat.h"
#include "sat_sdls.h"

#define EKID_TC 200u /* keyring slots used for the session keys */
#define EKID_TM 201u
#define EKID_TC_GS 202u
#define EKID_TM_GS 210u
#define EKID_ISL_TX 203u
#define EKID_ISL_RX 204u

static uint16_t        g_scid;
static int             g_isl;
static struct { uint16_t scid, tx_spi, rx_spi, ekid_tx, ekid_rx; } g_peers[SDLS_ISL_MAX];
static int             g_npeers;
static int             g_init;
static int             g_active;
static SatSdls_Stats_t g_st;

static void count(int32_t r, int tc)
{
    g_st.last_error = r;
    if (r == CRYPTO_LIB_SUCCESS)
    {
        tc ? g_st.tc_ok++ : g_st.tm_ok++;
    }
    else if (r == CRYPTO_LIB_ERR_MAC_VALIDATION_ERROR)
    {
        tc ? g_st.tc_bad_mac++ : g_st.tm_bad_mac++;
    }
    else if (r == CRYPTO_LIB_ERR_IV_OUTSIDE_WINDOW || r == CRYPTO_LIB_ERR_ARSN_OUTSIDE_WINDOW)
    {
        tc ? g_st.tc_replay++ : g_st.tm_replay++;
    }
    else
    {
        tc ? g_st.tc_other++ : g_st.tm_other++;
    }
}

int32_t SatSdls_Init(uint16_t scid)
{
    int32_t r;
    SaInterface sa_if;
    SecurityAssociation_t *sa;
    uint16_t i;

    if (g_init)
    {
        return CRYPTO_LIB_SUCCESS;
    }
    g_scid = scid;
#ifdef SAT_SDLS_LIBGCRYPT /* cross check build: NASA's default backend */
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_DISABLED, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_LIBGCRYPT,
                            IV_INTERNAL);
#else
    Crypto_Config_CryptoLib(KEY_TYPE_INTERNAL, MC_TYPE_DISABLED, SA_TYPE_INMEMORY, CRYPTOGRAPHY_TYPE_CUSTOM,
                            IV_INTERNAL);
#endif
    Crypto_Config_TC(CRYPTO_TC_CREATE_FECF_TRUE, TC_PROCESS_SDLS_PDUS_FALSE, TC_NO_PUS_HDR, TC_IGNORE_ANTI_REPLAY_FALSE,
                     TC_IGNORE_SA_STATE_FALSE, TC_UNIQUE_SA_PER_MAP_ID_FALSE, TC_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    Crypto_Config_TM(CRYPTO_TM_CREATE_FECF_TRUE, TM_IGNORE_ANTI_REPLAY_FALSE, TM_CHECK_FECF_TRUE, 0x3F,
                     SA_INCREMENT_NONTRANSMITTED_IV_TRUE);
    {
        TCGvcidManagedParameters_t tc = {0, 0, 0, TC_HAS_FECF, TC_HAS_SEGMENT_HDRS, 255, 1};
        TMGvcidManagedParameters_t tm = {0, 0, 0, TM_HAS_FECF, SDLS_TM_FRAME_LEN, TM_HAS_OCF, 1};
        tc.scid = scid;
        tc.vcid = SDLS_VC_USER;
        Crypto_Config_Add_TC_Gvcid_Managed_Parameters(tc);
        tc.vcid = SDLS_VC_GROUND;
        Crypto_Config_Add_TC_Gvcid_Managed_Parameters(tc);
        tm.scid = scid;
        tm.vcid = SDLS_VC_TM_USER;
        Crypto_Config_Add_TM_Gvcid_Managed_Parameters(tm);
        tm.vcid = SDLS_VC_ISL;
        Crypto_Config_Add_TM_Gvcid_Managed_Parameters(tm);
        tm.vcid = SDLS_VC_ISL_UP;
        Crypto_Config_Add_TM_Gvcid_Managed_Parameters(tm);
        tm.vcid = SDLS_VC_TM_GROUND;
        Crypto_Config_Add_TM_Gvcid_Managed_Parameters(tm);
    }
    r = Crypto_Init();
    if (r != CRYPTO_LIB_SUCCESS)
    {
        return r;
    }
    /* CryptoLib's in memory SA table comes populated with its unit test SAs:
       take every one out of service, only the testbed's two will run. */
    sa_if = get_sa_interface_inmemory();
    for (i = 0; i < NUM_SA; i++)
    {
        if (sa_if->sa_get_from_spi(i, &sa) == CRYPTO_LIB_SUCCESS && sa != NULL)
        {
            sa->sa_state = SA_NONE;
        }
    }
    g_init = 1;
    return CRYPTO_LIB_SUCCESS;
}

static int32_t configure_scid(uint16_t spi, uint16_t ekid, uint16_t scid, uint8_t vcid, int sender,
                              const uint8_t sk[32], const char *klabel, const char *ivlabel);

static int32_t configure(uint16_t spi, uint16_t ekid, uint8_t vcid, int sender, const uint8_t sk[32],
                         const char *klabel, const char *ivlabel)
{
    return configure_scid(spi, ekid, g_scid, vcid, sender, sk, klabel, ivlabel);
}

static int32_t configure_scid(uint16_t spi, uint16_t ekid, uint16_t scid, uint8_t vcid, int sender,
                              const uint8_t sk[32], const char *klabel, const char *ivlabel)
{
    SaInterface            sa_if = get_sa_interface_inmemory();
    KeyInterface           key_if = get_key_interface_internal();
    SecurityAssociation_t *sa = NULL;
    crypto_key_t          *k;
    uint8_t                iv_seed[32];
    int32_t                r;

    r = sa_if->sa_get_from_spi(spi, &sa);
    if (r != CRYPTO_LIB_SUCCESS || sa == NULL)
    {
        return r != CRYPTO_LIB_SUCCESS ? r : CRYPTO_LIB_ERROR;
    }
    k = key_if->get_key(ekid);
    if (k == NULL)
    {
        return CRYPTO_LIB_ERROR;
    }
    pqsat_kdf(k->value, sk, 32, klabel);
    k->key_len   = 32;
    k->key_state = KEY_ACTIVE;
    pqsat_kdf(iv_seed, sk, 32, ivlabel);

    sa->spi             = spi;
    sa->ekid            = ekid;
    sa->akid            = ekid;
    sa->gvcid_blk.tfvn  = 0;
    sa->gvcid_blk.scid  = scid;
    sa->gvcid_blk.vcid  = vcid;
    sa->gvcid_blk.mapid = 0;
    sa->est             = 1;
    sa->ast             = 1;
    sa->ecs_len         = 1;
    sa->ecs             = CRYPTO_CIPHER_AES256_GCM;
    sa->acs_len         = 0;
    sa->acs             = CRYPTO_MAC_NONE;
    sa->null_iv         = IV_NULL_FALSE;
    sa->iv_len          = 12;
    sa->shivf_len       = 12;
    memset(sa->iv, 0, sizeof sa->iv);
    memcpy(sa->iv, iv_seed, 4);
    sa->iv[11] = sender ? 1 : 0; /* see sat_sdls.h: senders start one above receivers */
    sa->null_arsn = ARSN_NULL_FALSE;
    sa->arsn_len  = 0;
    sa->shsnf_len = 0;
    sa->arsnw_len = 1;
    sa->arsnw     = SDLS_ARSN_WINDOW;
    sa->shplf_len = 0;
    sa->stmacf_len = SDLS_MAC_LEN;
    /* authenticate the whole of the primary, segment and security headers */
    sa->abm_len = ABM_SIZE;
    memset(sa->abm, 0xFF, ABM_SIZE);
    sa->sa_state = SA_OPERATIONAL;
    return CRYPTO_LIB_SUCCESS;
}

/* satellite side, one link at a time */
int32_t SatSdls_LinkRx(const uint8_t sk[32], int link)
{
    int32_t r;

    if (!g_init)
    {
        return CRYPTO_LIB_ERR_NO_INIT;
    }
    r = (link == SDLS_LINK_USER)
            ? configure(SDLS_SPI_TC, EKID_TC, SDLS_VC_USER, 0, sk, "SDLS TC VC1 key", "SDLS TC VC1 iv")
            : configure(SDLS_SPI_TC_GS, EKID_TC_GS, SDLS_VC_GROUND, 0, sk, "SDLS TC VC0 key", "SDLS TC VC0 iv");
    if (r == CRYPTO_LIB_SUCCESS)
    {
        g_active = 1;
    }
    return r;
}

int32_t SatSdls_LinkTx(const uint8_t sk[32], int link)
{
    int32_t r;

    if (!g_init)
    {
        return CRYPTO_LIB_ERR_NO_INIT;
    }
    r = (link == SDLS_LINK_USER)
            ? configure(SDLS_SPI_TM, EKID_TM, SDLS_VC_TM_USER, 1, sk, "SDLS TM VC2 key", "SDLS TM VC2 iv")
            : configure(SDLS_SPI_TM_GS, EKID_TM_GS, SDLS_VC_TM_GROUND, 1, sk, "SDLS TM VC4 key", "SDLS TM VC4 iv");
    if (r == CRYPTO_LIB_SUCCESS)
    {
        g_active = 1;
    }
    return r;
}

static void stop_spis(const uint16_t *spis, const uint16_t *kids, int count)
{
    SaInterface            sa_if = get_sa_interface_inmemory();
    KeyInterface           key_if = get_key_interface_internal();
    SecurityAssociation_t *sa;
    crypto_key_t          *k;
    int                    i;

    for (i = 0; i < count; i++)
    {
        if (sa_if->sa_get_from_spi(spis[i], &sa) == CRYPTO_LIB_SUCCESS && sa)
        {
            sa->sa_state = SA_NONE;
        }
        if ((k = key_if->get_key(kids[i])) != NULL)
        {
            memset(k->value, 0, sizeof k->value);
            k->key_state = 0;
        }
    }
}

void SatSdls_LinkStop(int link)
{
    const uint16_t su[2] = {SDLS_SPI_TC, SDLS_SPI_TM}, ku[2] = {EKID_TC, EKID_TM};
    const uint16_t sg[2] = {SDLS_SPI_TC_GS, SDLS_SPI_TM_GS}, kg[2] = {EKID_TC_GS, EKID_TM_GS};

    if (!g_init)
    {
        return;
    }
    if (link == SDLS_LINK_USER)
    {
        stop_spis(su, ku, 2);
    }
    else
    {
        stop_spis(sg, kg, 2);
    }
}

static int32_t start_rx(const uint8_t sk[32], int role)
{
    int32_t r = CRYPTO_LIB_SUCCESS;

    if (role == SDLS_ROLE_SATELLITE)
    {
        r = SatSdls_LinkRx(sk, SDLS_LINK_USER);
        if (r == CRYPTO_LIB_SUCCESS)
        {
            r = SatSdls_LinkRx(sk, SDLS_LINK_GROUND);
        }
    }
    else if (role == SDLS_ROLE_USER)
    {
        r = configure(SDLS_SPI_TM, EKID_TM, SDLS_VC_TM_USER, 0, sk, "SDLS TM VC2 key", "SDLS TM VC2 iv");
    }
    else
    {
        r = configure(SDLS_SPI_TM_GS, EKID_TM_GS, SDLS_VC_TM_GROUND, 0, sk, "SDLS TM VC4 key", "SDLS TM VC4 iv");
    }
    return r;
}

static int32_t start_tx(const uint8_t sk[32], int role)
{
    int32_t r;

    if (role == SDLS_ROLE_SATELLITE)
    {
        r = SatSdls_LinkTx(sk, SDLS_LINK_USER);
        if (r == CRYPTO_LIB_SUCCESS)
        {
            r = SatSdls_LinkTx(sk, SDLS_LINK_GROUND);
        }
        return r;
    }
    if (role == SDLS_ROLE_USER)
    {
        return configure(SDLS_SPI_TC, EKID_TC, SDLS_VC_USER, 1, sk, "SDLS TC VC1 key", "SDLS TC VC1 iv");
    }
    return configure(SDLS_SPI_TC_GS, EKID_TC_GS, SDLS_VC_GROUND, 1, sk, "SDLS TC VC0 key", "SDLS TC VC0 iv");
}

int32_t SatSdls_StartRx(const uint8_t sk[32], int role)
{
    int32_t r;

    if (!g_init)
    {
        return CRYPTO_LIB_ERR_NO_INIT;
    }
    r = start_rx(sk, role);
    if (r == CRYPTO_LIB_SUCCESS)
    {
        g_active = 1;
    }
    return r;
}

int32_t SatSdls_StartTx(const uint8_t sk[32], int role)
{
    int32_t r;

    if (!g_init)
    {
        return CRYPTO_LIB_ERR_NO_INIT;
    }
    r = start_tx(sk, role);
    if (r == CRYPTO_LIB_SUCCESS)
    {
        g_active = 1;
    }
    return r;
}

int32_t SatSdls_Start(const uint8_t sk[32], int role)
{
    int32_t r = SatSdls_StartRx(sk, role);

    if (r == CRYPTO_LIB_SUCCESS)
    {
        r = SatSdls_StartTx(sk, role);
    }
    return r;
}

void SatSdls_Stop(void)
{
    if (!g_init)
    {
        return;
    }
    SatSdls_LinkStop(SDLS_LINK_USER);
    SatSdls_LinkStop(SDLS_LINK_GROUND);
    g_active = 0;
}

int SatSdls_Active(void)
{
    return g_active;
}

int32_t SatSdls_IslStart(const uint8_t kisl[32], uint16_t peerScid)
{
    char     ktx[40], itx[40], krx[40], irx[40];
    int32_t  r;
    int      i;
    uint16_t lo, hi, spiLoHi, spiHiLo;

    if (!g_init)
    {
        return CRYPTO_LIB_ERR_NO_INIT;
    }
    for (i = 0; i < g_npeers && g_peers[i].scid != peerScid; i++)
    {
    }
    if (i == g_npeers)
    {
        TMGvcidManagedParameters_t tm = {0, 0, 0, TM_HAS_FECF, SDLS_TM_FRAME_LEN, TM_HAS_OCF, 1};
        if (g_npeers >= SDLS_ISL_MAX)
        {
            return CRYPTO_LIB_ERROR;
        }
        tm.scid = peerScid;
        tm.vcid = SDLS_VC_ISL;
        r = Crypto_Config_Add_TM_Gvcid_Managed_Parameters(tm);
        tm.vcid = SDLS_VC_ISL_UP;
        if (r == CRYPTO_LIB_SUCCESS)
        {
            r = Crypto_Config_Add_TM_Gvcid_Managed_Parameters(tm);
        }
        if (r != CRYPTO_LIB_SUCCESS)
        {
            return r;
        }
        g_peers[i].scid    = peerScid;
        g_peers[i].ekid_tx = (uint16_t)(EKID_ISL_TX + 2 * i);
        g_peers[i].ekid_rx = (uint16_t)(EKID_ISL_RX + 2 * i);
        g_npeers++;
    }
    lo = g_scid < peerScid ? g_scid : peerScid;
    hi = g_scid < peerScid ? peerScid : g_scid;
    spiLoHi = (uint16_t)(SDLS_SPI_ISL_BASE + 2 * (hi & 0xF));
    spiHiLo = (uint16_t)(spiLoHi + 1);
    g_peers[i].tx_spi = (g_scid == lo) ? spiLoHi : spiHiLo;
    g_peers[i].rx_spi = (g_scid == lo) ? spiHiLo : spiLoHi;
    snprintf(ktx, sizeof ktx, "SDLS ISL %04X>%04X key", g_scid, peerScid);
    snprintf(itx, sizeof itx, "SDLS ISL %04X>%04X iv", g_scid, peerScid);
    snprintf(krx, sizeof krx, "SDLS ISL %04X>%04X key", peerScid, g_scid);
    snprintf(irx, sizeof irx, "SDLS ISL %04X>%04X iv", peerScid, g_scid);
    /* this satellite sends toward a higher SCID on VC_ISL_UP and toward a lower one on VC_ISL;
       the neighbour does the same, so its frames to us arrive on the opposite channel */
    r = configure_scid(g_peers[i].tx_spi, g_peers[i].ekid_tx, g_scid, g_scid < peerScid ? SDLS_VC_ISL_UP : SDLS_VC_ISL,
                       1, kisl, ktx, itx);
    if (r == CRYPTO_LIB_SUCCESS)
    {
        r = configure_scid(g_peers[i].rx_spi, g_peers[i].ekid_rx, peerScid,
                           peerScid < g_scid ? SDLS_VC_ISL_UP : SDLS_VC_ISL, 0, kisl, krx, irx);
    }
    if (r == CRYPTO_LIB_SUCCESS)
    {
        g_isl = 1;
    }
    return r;
}

void SatSdls_IslStop(void)
{
    int i;

    if (!g_init)
    {
        return;
    }
    for (i = 0; i < g_npeers; i++)
    {
        uint16_t spis[2] = {g_peers[i].tx_spi, g_peers[i].rx_spi};
        uint16_t kids[2] = {g_peers[i].ekid_tx, g_peers[i].ekid_rx};
        stop_spis(spis, kids, 2);
    }
    g_isl = 0;
}

int SatSdls_IslActive(void)
{
    return g_isl;
}

uint8_t SatSdls_IslVc(uint16_t ownScid, uint16_t peerScid)
{
    return ownScid < peerScid ? SDLS_VC_ISL_UP : SDLS_VC_ISL;
}

int32_t SatSdls_IslApply(uint8_t *frame, uint16_t peerScid)
{
    int i;

    for (i = 0; i < g_npeers && g_peers[i].scid != peerScid; i++)
    {
    }
    if (i == g_npeers)
    {
        return CRYPTO_LIB_ERROR;
    }
    /* CryptoLib selects the association by the frame's SCID and VCID and writes the SPI itself;
       the caller built the frame on the channel for this neighbour (SatSdls_IslVc) */
    (void)i;
    return Crypto_TM_ApplySecurity(frame, SDLS_TM_FRAME_LEN);
}

int32_t SatSdls_TcApply(const uint8_t *in, int inlen, uint8_t *out, int outmax, int *outlen)
{
    uint8_t *enc = NULL;
    uint16_t elen = 0;
    int32_t  r;

    r = Crypto_TC_ApplySecurity(in, (uint16_t)inlen, &enc, &elen);
    if (r == CRYPTO_LIB_SUCCESS)
    {
        if ((int)elen > outmax)
        {
            r = CRYPTO_LIB_ERR_BUFFER_SIZE;
        }
        else
        {
            memcpy(out, enc, elen);
            *outlen = elen;
        }
    }
    free(enc);
    return r;
}

int32_t SatSdls_TcProcess(const uint8_t *in, int inlen, uint8_t *seg, uint8_t *pdu, int pdumax, int *pdulen)
{
    static TC_t tc;
    static uint8_t buf[1024];
    int            len = inlen;
    int32_t        r;

    if (inlen < 6 || inlen > (int)sizeof buf)
    {
        return CRYPTO_LIB_ERR_INPUT_FRAME_TOO_SHORT_FOR_TC_STANDARD;
    }
    memcpy(buf, in, (size_t)inlen); /* CryptoLib may work in place */
    memset(&tc, 0, sizeof tc);
    r = Crypto_TC_ProcessSecurity(buf, &len, &tc);
    if (r == CRYPTO_LIB_SUCCESS)
    {
        if ((int)tc.tc_pdu_len > pdumax)
        {
            r = CRYPTO_LIB_ERR_BUFFER_SIZE;
        }
        else
        {
            *seg = in[5];
            memcpy(pdu, tc.tc_pdu, tc.tc_pdu_len);
            *pdulen = tc.tc_pdu_len;
        }
    }
    count(r, 1);
    return r;
}

int32_t SatSdls_TmApply(uint8_t *frame)
{
    /* the SPI is written by the caller's layout here; CryptoLib fills IV,
       encrypts the data field, writes the MAC and the FECF */
    uint16_t spi = (((frame[1] >> 1) & 7) == SDLS_VC_TM_GROUND) ? SDLS_SPI_TM_GS : SDLS_SPI_TM;
    frame[6] = (uint8_t)(spi >> 8);
    frame[7] = (uint8_t)spi;
    return Crypto_TM_ApplySecurity(frame, SDLS_TM_FRAME_LEN);
}

int32_t SatSdls_TmProcess(const uint8_t *in, int inlen, uint8_t *data, int datamax, int *datalen)
{
    static TM_t    tm;
    static uint8_t buf[SDLS_TM_FRAME_LEN];
    uint16_t       dlen = 0;
    int32_t        r;

    if (inlen != SDLS_TM_FRAME_LEN)
    {
        count(CRYPTO_LIB_ERR_TM_FL_LT_MAX_FRAME_SIZE, 0);
        return CRYPTO_LIB_ERR_TM_FL_LT_MAX_FRAME_SIZE;
    }
    memcpy(buf, in, SDLS_TM_FRAME_LEN);
    memset(&tm, 0, sizeof tm);
    r = Crypto_TM_ProcessSecurity(buf, SDLS_TM_FRAME_LEN, &tm, &dlen);
    if (r == CRYPTO_LIB_SUCCESS)
    {
        if ((int)tm.tm_pdu_len > datamax)
        {
            r = CRYPTO_LIB_ERR_BUFFER_SIZE;
        }
        else
        {
            memcpy(data, tm.tm_pdu, tm.tm_pdu_len);
            *datalen = tm.tm_pdu_len;
        }
    }
    count(r, 0);
    return r;
}

void SatSdls_GetStats(SatSdls_Stats_t *st)
{
    *st = g_st;
}
