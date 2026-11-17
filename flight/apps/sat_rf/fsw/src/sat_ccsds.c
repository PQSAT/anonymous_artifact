/* sat_ccsds.c  -  CCSDS satellite link core, C version.  See sat_ccsds.h. */
#include "sat_ccsds.h"
#include "sat_auth.h"
#include "sat_sdls.h"
#include <stdio.h>
#include <string.h>

/* ---------------- CRC-16-CCITT (FECF) ---------------- */
uint16_t Sat_Crc16(const uint8_t *d, int n)
{
    uint16_t c = 0xFFFF;
    int      i, b;

    for (i = 0; i < n; i++)
    {
        c ^= (uint16_t)d[i] << 8;
        for (b = 0; b < 8; b++)
        {
            c = (c & 0x8000) ? (uint16_t)((c << 1) ^ 0x1021) : (uint16_t)(c << 1);
        }
    }
    return c;
}

/* ---------------- TC transfer frame ---------------- */
int Sat_ParseTc(const uint8_t *b, int n, Sat_TcFrame_t *f)
{
    int flen;

    if (n < 7)
    {
        return SAT_TC_SHORT;
    }
    if ((b[0] >> 6) != 0)
    {
        return SAT_TC_VERSION;
    }
    flen = (((b[2] & 0x03) << 8) | b[3]) + 1;
    if (flen != n)
    {
        return SAT_TC_LENGTH;
    }
    if (Sat_Crc16(b, n - 2) != (uint16_t)((b[n - 2] << 8) | b[n - 1]))
    {
        return SAT_TC_CRC;
    }
    f->bypass = (b[0] & 0x20) != 0;
    f->ctrl   = (b[0] & 0x10) != 0;
    f->scid   = (uint16_t)(((b[0] & 0x03) << 8) | b[1]);
    f->vcid   = (uint8_t)(b[2] >> 2);
    f->ns     = b[4];
    f->data   = b + 5;
    f->dlen   = n - 7;
    return SAT_TC_OK;
}

/* ---------------- TM transfer frame ---------------- */
int Sat_BuildTm(uint8_t *out, uint16_t scid, uint8_t vcid, uint8_t mcfc, uint8_t vcfc, const uint8_t *pkt, int plen,
                const uint8_t clcw[4], uint16_t fhp)
{
    uint16_t dfs;
    uint16_t c;
    int      k;

    if (6 + plen + 4 + 2 > SAT_MAX_FRAME)
    {
        return 0;
    }
    out[0] = (uint8_t)((scid >> 4) & 0x3F);                                    /* version 00 + SCID[9:4] */
    out[1] = (uint8_t)(((scid & 0x0F) << 4) | ((vcid & 0x07) << 1) | 0x01);    /* SCID[3:0], VCID, OCF flag */
    out[2] = mcfc;
    out[3] = vcfc;
    dfs    = (uint16_t)((3u << 11) | (fhp & 0x7FFu)); /* segment length id 11, first header pointer */
    out[4] = (uint8_t)(dfs >> 8);
    out[5] = (uint8_t)(dfs & 0xFF);
    memcpy(out + 6, pkt, (size_t)plen);
    k = 6 + plen;
    memcpy(out + k, clcw, 4);
    k += 4;
    c        = Sat_Crc16(out, k);
    out[k++] = (uint8_t)(c >> 8);
    out[k++] = (uint8_t)(c & 0xFF);
    return k;
}

/* ---------------- space packet ---------------- */
int Sat_BuildPacket(uint8_t *out, uint8_t type, uint16_t apid, uint16_t seq, const uint8_t *shdr, int shlen,
                    const uint8_t *d, int dlen)
{
    return Sat_BuildPacketF(out, type, apid, seq, SAT_SEQF_UNSEG, shdr, shlen, d, dlen);
}

int Sat_BuildPacketF(uint8_t *out, uint8_t type, uint16_t apid, uint16_t seq, uint8_t seqFlags,
                     const uint8_t *shdr, int shlen, const uint8_t *d, int dlen)
{
    int L = shlen + dlen;

    out[0] = (uint8_t)((type << 4) | (shlen ? 0x08 : 0) | ((apid >> 8) & 0x07));
    out[1] = (uint8_t)(apid & 0xFF);
    out[2] = (uint8_t)(((seqFlags & 3u) << 6) | ((seq >> 8) & 0x3F));
    out[3] = (uint8_t)(seq & 0xFF);
    out[4] = (uint8_t)((L - 1) >> 8);
    out[5] = (uint8_t)((L - 1) & 0xFF);
    if (shlen)
    {
        memcpy(out + 6, shdr, (size_t)shlen);
    }
    memcpy(out + 6 + shlen, d, (size_t)dlen);
    return 6 + L;
}

/* ---------------- FARM-1 ---------------- */
void Sat_FarmInit(Sat_Farm_t *farm)
{
    memset(farm, 0, sizeof(*farm));
    farm->window = 10;
}

Sat_FarmResult_t Sat_FarmOnFrame(Sat_Farm_t *farm, const Sat_TcFrame_t *f)
{
    uint8_t ahead;

    if (f->bypass)
    {
        if (f->ctrl)
        {
            /* Type-BC: control command */
            if (f->dlen == 1 && f->data[0] == 0x00) /* Unlock */
            {
                farm->lockout    = false;
                farm->wait       = false;
                farm->retransmit = false;
                farm->farmB      = (uint8_t)((farm->farmB + 1) & 3);
                return SAT_FARM_ACCEPT_BC;
            }
            if (f->dlen == 3 && f->data[0] == 0x82 && f->data[1] == 0x00) /* Set V(R) */
            {
                if (!farm->lockout)
                {
                    farm->vr         = f->data[2];
                    farm->retransmit = false;
                    farm->wait       = false;
                }
                farm->farmB = (uint8_t)((farm->farmB + 1) & 3);
                return SAT_FARM_ACCEPT_BC;
            }
            return SAT_FARM_DISCARD;
        }
        farm->farmB = (uint8_t)((farm->farmB + 1) & 3); /* Type-BD: expedited data */
        return SAT_FARM_ACCEPT_BD;
    }

    if (f->ctrl || farm->lockout)
    {
        return SAT_FARM_DISCARD; /* Type-AD: sequence controlled */
    }
    ahead = (uint8_t)(f->ns - farm->vr);
    if (ahead == 0)
    {
        farm->vr++;
        farm->retransmit = false;
        return SAT_FARM_ACCEPT_AD;
    }
    if (ahead < farm->window / 2)
    {
        farm->retransmit = true; /* gap: ask for retransmission */
        return SAT_FARM_DISCARD;
    }
    if ((uint8_t)(farm->vr - f->ns) <= farm->window / 2)
    {
        return SAT_FARM_DISCARD; /* already received (duplicate) */
    }
    farm->lockout = true; /* outside both windows */
    return SAT_FARM_DISCARD;
}

void Sat_FarmClcw(const Sat_Farm_t *farm, uint8_t vcid, uint8_t out[4])
{
    out[0] = 0x01; /* type 0, version 00, status 000, COP-1 in effect */
    out[1] = (uint8_t)((vcid & 0x3F) << 2);
    out[2] = (uint8_t)(((farm->lockout ? 1 : 0) << 5) | ((farm->wait ? 1 : 0) << 4) |
                       ((farm->retransmit ? 1 : 0) << 3) | ((farm->farmB & 3) << 1));
    out[3] = farm->vr; /* report value N(R) */
}

/* ---------------- the satellite ---------------- */
static void Sat_Say(Sat_Core_t *s, const char *m)
{
    if (s->log)
    {
        s->log(m, s->ctx);
    }
}

static void Sat_Cuc(Sat_Core_t *s, uint8_t out[6])
{
    uint32_t el   = s->now - s->timeBaseMs;
    uint32_t sec  = s->timeBaseSec + el / 1000u;
    uint16_t fine = (uint16_t)(((el % 1000u) * 65536u) / 1000u);

    out[0] = (uint8_t)(sec >> 24);
    out[1] = (uint8_t)(sec >> 16);
    out[2] = (uint8_t)(sec >> 8);
    out[3] = (uint8_t)(sec);
    out[4] = (uint8_t)(fine >> 8);
    out[5] = (uint8_t)(fine & 0xFF);
}

static bool Sat_StartSpan(Sat_Core_t *s, uint8_t vc, uint8_t clcwVc, const uint8_t *pkt, int plen);
static uint8_t Sat_PickClcwVc(Sat_Core_t *s, uint8_t preferred);
static bool Sat_QueueFrame(Sat_Core_t *s, uint8_t vc, uint8_t clcwVc, const uint8_t *pkt, int plen, uint16_t fhp,
                           uint32_t delay);
static int Sat_RelayDfMax(const Sat_Core_t *s, uint8_t link);
static void Sat_IslSendCtl(Sat_Core_t *s, int peer, uint16_t apid, const uint8_t *data, int dlen);
static void Sat_IslSendBig(Sat_Core_t *s, int peer, uint16_t apid, const uint8_t *data, int dlen);
static void Sat_RefreshClcw(Sat_Core_t *s, uint8_t *frame, int n);
static void Sat_ChunkStart(Sat_Core_t *s, uint16_t dst, uint8_t clcwVc, const uint8_t *data, int len);
static void Sat_ChunkDrain(Sat_Core_t *s);
static uint8_t Sat_OnNak(Sat_Core_t *s, uint8_t vc, const uint8_t *d, int dlen);
static bool Sat_QueueTmChunk(Sat_Core_t *s, uint8_t vc, uint8_t clcwVc, const uint8_t *chunk, int clen, uint16_t fhp);

/* Build a TM frame (TM packet with CUC secondary header) and queue it. */
static void Sat_QueueTm(Sat_Core_t *s, uint8_t vc, uint16_t apid, uint16_t *seq, const uint8_t *d, int dlen,
                        uint8_t clcwVc, uint32_t delay)
{
    static uint8_t pkt[SAT_BIGTM_MAX]; /* static: larger than the task stack */
    uint8_t t[6];
    int     plen;

    if (dlen < 0 || dlen + 12 > SAT_BIGTM_MAX)
    {
        Sat_Say(s, "telemetry payload too large, dropped");
        return;
    }
    Sat_Cuc(s, t);
    plen = Sat_BuildPacket(pkt, 0, apid, *seq, t, 6, d, dlen);
    *seq = (uint16_t)((*seq + 1) & 0x3FFF);

    /* a packet larger than one frame data field is spanned across frames */
    if (plen > (vc == SAT_TM_VC_RELAY ? Sat_RelayDfMax(s, clcwVc) : SAT_TM_DF_MAX))
    {
        (void)Sat_StartSpan(s, vc, clcwVc, pkt, plen);
        return;
    }
    if (!Sat_QueueFrame(s, vc, clcwVc, pkt, plen, 0u, delay))
    {
        Sat_Say(s, "TX queue full, frame dropped");
    }
}

/* Frame data field available on the relay channel to the terminal whose TC
 * virtual channel is link: smaller under SDLS. */
static int Sat_RelayDfMax(const Sat_Core_t *s, uint8_t link)
{
    return s->sdls[link % SAT_TC_VC_COUNT].txActive ? SAT_SDLS_TM_DF_MAX : SAT_TM_DF_MAX;
}

/* Build one TM frame carrying pkt and queue it.  On the relay channel with
 * SDLS running the frame goes on TM VC2 in the fixed SDLS layout, with the
 * data field filled by an idle packet; SPI, IV, MAC and FECF are written at
 * transmit time by CryptoLib so the IV sequence matches the air order. */
static bool Sat_QueueFrame(Sat_Core_t *s, uint8_t vc, uint8_t clcwVc, const uint8_t *pkt, int plen, uint16_t fhp,
                           uint32_t delay)
{
    uint8_t cl[4];
    int     i;
    int     n;
    bool    secure = (vc == SAT_TM_VC_RELAY && s->sdls[clcwVc % SAT_TC_VC_COUNT].txActive);

    for (i = 0; i < SAT_TXQ_LEN; i++)
    {
        if (s->q[i].n != 0)
        {
            continue;
        }
        if (secure)
        {
            uint8_t *f    = s->q[i].b;
            int      room = SAT_SDLS_TM_DF_MAX;
            uint16_t dfs;
            int      k;

            if (plen > room)
            {
                return false;
            }
            vc   = (clcwVc == SAT_TC_VC_GROUND) ? SAT_TM_VC_SECURE_GS : SAT_TM_VC_SECURE;
            f[0] = (uint8_t)((s->scid >> 4) & 0x3F);
            f[1] = (uint8_t)(((s->scid & 0x0F) << 4) | ((vc & 0x07) << 1) | 0x01);
            f[2] = s->mcfc;
            f[3] = s->vcfc[vc];
            dfs  = (uint16_t)((3u << 11) | (fhp & 0x7FFu));
            f[4] = (uint8_t)(dfs >> 8);
            f[5] = (uint8_t)(dfs & 0xFF);
            memset(f + 6, 0, SDLS_HDR_LEN);
            k = 6 + SDLS_HDR_LEN;
            memcpy(f + k, pkt, (size_t)plen);
            k += plen;
            if (room - plen >= 7)
            {
                /* an idle packet fills the rest of the fixed length data field */
                static const uint8_t fill[SAT_SDLS_TM_DF_MAX] = {0};
                k += Sat_BuildPacket(f + k, 0, SAT_APID_IDLE, s->idleSeq, NULL, 0, fill, room - plen - 6);
                s->idleSeq = (uint16_t)((s->idleSeq + 1) & 0x3FFF);
            }
            else if (room - plen > 0)
            {
                memset(f + k, 0, (size_t)(room - plen));
                k += room - plen;
            }
            memset(f + k, 0, SDLS_MAC_LEN); /* MAC, OCF and FECF are written at transmit time */
            k += SDLS_MAC_LEN;
            Sat_FarmClcw(&s->farm[clcwVc], clcwVc, f + k);
            k += 4;
            f[k++] = 0;
            f[k++] = 0;
            n = k;
        }
        else
        {
            Sat_FarmClcw(&s->farm[clcwVc], clcwVc, cl); /* placeholder, rewritten at transmit time */
            n = Sat_BuildTm(s->q[i].b, s->scid, vc, s->mcfc, s->vcfc[vc], pkt, plen, cl, fhp);
            if (n == 0)
            {
                return false;
            }
        }
        s->mcfc++;
        s->vcfc[vc]++;
        s->q[i].n      = n;
        s->q[i].due    = s->now + delay;
        s->q[i].secure = secure;
        return true;
    }
    return false;
}

/* LoRa time on air, explicit header and CRC on, same formula as the ground. */
static unsigned Sat_LoraSf = SAT_LORA_SF;

/* The spreading factor of the satellite radio.  The air time of a frame follows from it, and
 * the transmit pacing and the receive window follow from the air time. */
void Sat_SetLoraSf(unsigned sf)
{
    if (sf >= 7u && sf <= 12u)
    {
        Sat_LoraSf = sf;
    }
}

uint32_t Sat_AirtimeMs(int nbytes)
{
    double ts  = (double)(1u << Sat_LoraSf) / (double)SAT_LORA_BW_HZ * 1000.0;
    int    de  = (ts > 16.0) ? 1 : 0;
    int    num = 8 * nbytes - 4 * (int)Sat_LoraSf + 28 + 16;
    int    den = 4 * ((int)Sat_LoraSf - 2 * de);
    int    sym = (num + den - 1) / den;
    double n   = 8.0 + (double)((sym > 0 ? sym : 0) * ((int)SAT_LORA_CR + 4));

    return (uint32_t)(((double)SAT_LORA_PREAMBLE + 4.25 + n) * ts + 0.5);
}

/* The OCF of a frame is written at transmit time, not at build time, so a
 * frame built ahead carries the FARM state current when it actually leaves:
 * a VC with a pending report takes the OCF, otherwise the VC the frame was
 * built for keeps it, refreshed.  The CRC is recomputed. */
static void Sat_RefreshClcw(Sat_Core_t *s, uint8_t *frame, int n)
{
    uint8_t  vc;
    uint16_t crc;
    int      ocf = n - 6;

    if (n < 12)
    {
        return;
    }
    vc = (uint8_t)((frame[ocf + 1] >> 2) & 0x3F);
    if (vc >= SAT_TC_VC_COUNT)
    {
        vc = 0;
    }
    vc = Sat_PickClcwVc(s, vc);
    Sat_FarmClcw(&s->farm[vc], vc, frame + ocf);
    crc          = Sat_Crc16(frame, n - 2);
    frame[n - 2] = (uint8_t)(crc >> 8);
    frame[n - 1] = (uint8_t)(crc & 0xFF);
}

/* Pick the TC VC whose CLCW the next frame carries: a VC with a pending
 * report first, alternating when more than one is pending, otherwise the
 * preferred VC. */
static uint8_t Sat_PickClcwVc(Sat_Core_t *s, uint8_t preferred)
{
    uint8_t i;
    uint8_t v;

    for (i = 1; i <= SAT_TC_VC_COUNT; i++)
    {
        v = (uint8_t)((s->clcwLast + i) % SAT_TC_VC_COUNT);
        if (s->clcwPending[v])
        {
            s->clcwPending[v] = false;
            s->clcwLast       = v;
            return v;
        }
    }
    return preferred;
}

static void Sat_QueueIdle(Sat_Core_t *s, uint8_t tcVc)
{
    uint8_t d = 0x55;

    s->clcwPending[tcVc] = true;
    /* while a spanned or chunked message is going out, its next frame carries the report */
    if (s->bigActive)
    {
        return;
    }
    {
        unsigned k;

        for (k = 0; k < SAT_CHUNK_SLOTS; k++)
        {
            if (s->chunk[k].valid && (s->chunk[k].next < s->chunk[k].total || s->chunk[k].retxCount))
            {
                return;
            }
        }
    }
    Sat_QueueTm(s, SAT_TM_VC_HK, SAT_APID_IDLE, &s->idleSeq, &d, 1, tcVc, SAT_TURNAROUND_MS);
}

static void Sat_SendHk(Sat_Core_t *s)
{
    uint32_t up = s->now / 1000u;
    uint8_t  d[28];
    uint16_t c[6];
    uint16_t per;
    uint8_t  vc;
    int      k = 0;
    int      i;

    d[k++] = (uint8_t)(s->scid >> 8);
    d[k++] = (uint8_t)(s->scid);
    d[k++] = (uint8_t)(up >> 24);
    d[k++] = (uint8_t)(up >> 16);
    d[k++] = (uint8_t)(up >> 8);
    d[k++] = (uint8_t)(up);
    per    = (uint16_t)(s->hkPeriodMs / 1000u);
    d[k++] = (uint8_t)(per >> 8);
    d[k++] = (uint8_t)(per);
    d[k++] = (uint8_t)(s->timeSet ? 1 : 0);
    d[k++] = (uint8_t)((s->lastRxBeat && (s->now - s->lastRxBeat) < 6000u) ? 1 : 0);

    c[0] = s->rxFrames;
    c[1] = s->crcErr;
    c[2] = s->idErr;
    c[3] = s->farmDiscard;
    c[4] = s->cmdsOk;
    c[5] = s->relayed;
    for (i = 0; i < 6; i++)
    {
        d[k++] = (uint8_t)(c[i] >> 8);
        d[k++] = (uint8_t)(c[i] & 0xFF);
    }
    d[k++] = (uint8_t)s->lastRssi;
    d[k++] = (uint8_t)s->lastSnr;
    d[k++] = s->farm[0].vr;
    d[k++] = s->farm[1].vr;

    vc          = s->clcwTurn;
    s->clcwTurn = (uint8_t)((s->clcwTurn + 1) % SAT_TC_VC_COUNT);
    Sat_QueueTm(s, SAT_TM_VC_HK, SAT_APID_HK, &s->hkSeq, d, k, vc, 0);
}

static void Sat_SendAck(Sat_Core_t *s, uint16_t tcSeq, uint8_t cmd, uint8_t st, uint8_t tcVc)
{
    uint8_t d[4];

    d[0] = (uint8_t)(tcSeq >> 8);
    d[1] = (uint8_t)(tcSeq);
    d[2] = cmd;
    d[3] = st;
    Sat_QueueTm(s, SAT_TM_VC_HK, SAT_APID_TC_ACK, &s->ackSeq, d, 4, tcVc, SAT_TURNAROUND_MS);
}

/* Execute a ground command (from the ground station's channel, or forwarded
 * over the ISL by the neighbour on the ground station's behalf). */
static uint8_t Sat_ExecCommand(Sat_Core_t *s, uint8_t cmd, const uint8_t *d, int dlen)
{
    uint8_t st = SAT_ST_OK;
    char    buf[96];

    if (cmd == SAT_CMD_PING)
    {
        /* nothing to do */
    }
    else if (cmd == SAT_CMD_SA_STOP)
    {
        Sat_SdlsStop(s);
    }
    else if (cmd == SAT_CMD_SET_HK_RATE)
    {
        if (dlen == 3)
        {
            uint16_t sec = (uint16_t)((d[1] << 8) | d[2]);

            if (sec >= 2 && sec <= 60)
            {
                s->hkPeriodMs = (uint32_t)sec * 1000u;
            }
            else
            {
                st = SAT_ST_BAD_ARG;
            }
        }
        else
        {
            st = SAT_ST_BAD_ARG;
        }
    }
    else if (cmd == SAT_CMD_SET_TIME)
    {
        if (dlen == 5)
        {
            s->timeBaseSec = ((uint32_t)d[1] << 24) | ((uint32_t)d[2] << 16) | ((uint32_t)d[3] << 8) | d[4];
            s->timeBaseMs  = s->now;
            s->timeSet     = true;
        }
        else
        {
            st = SAT_ST_BAD_ARG;
        }
    }
    else if (cmd == SAT_CMD_HANDOVER)
    {
        /* hand over order: user 2 | target SCID 2 | HMAC(K_ord, "HANDOVER" | user | serving | target) 32.
         * The MAC is under the key of the user the order names, so the key of the ground link
         * or of another user's session does not make a valid order. */
        uint16_t user = dlen >= 5 ? (uint16_t)((d[1] << 8) | d[2]) : 0;
        uint16_t dst  = dlen >= 5 ? (uint16_t)((d[3] << 8) | d[4]) : 0;
        int      next = Sat_IslRoute(s, dst, -1);
        uint8_t  mac[32];
        if (dlen != 5 + 32 || next < 0 || s->islTx == NULL || s->xferBuild == NULL)
        {
            st = SAT_ST_BAD_ARG;
        }
        else if (!s->isl[next].secure || !s->sdls[SAT_TC_VC_USER1].rxActive || !s->sessValid)
        {
            Sat_Say(s, "handover refused: no user session or ISL in clear");
            st = SAT_ST_NOT_ALLOWED;
        }
        else if (Auth_OrderMac(mac, s->sessOrd, user, s->scid, dst), memcmp(mac, d + 5, 32) != 0)
        {
            s->ordersRejected++;
            Sat_Say(s, "handover refused: the order does not verify under the key of this user");
            st = SAT_ST_NOT_ALLOWED;
        }
        else
        {
            static uint8_t x[AUTH_XFER_LEN];
            uint8_t        skn[32];
            int            n;
            Auth_NextLinkKey(skn, s->sessSk, dst);
            n = s->xferBuild(s->xferCtx, AUTH_XFER_USERSESS, dst, user, skn, Sat_NowSec(s), x);
            memset(skn, 0, sizeof skn);
            if (n < 0)
            {
                Sat_Say(s, "handover refused: no certificate of the target satellite");
                st = SAT_ST_BAD_ARG;
            }
            else
            {
                Sat_IslSendBig(s, next, SAT_APID_USERSESS, x, n);
                s->xferSent++;
                /* the user is gone: erase SK, K_ord and the user link association */
                memset(s->sessSk, 0, sizeof s->sessSk);
                memset(s->sessOrd, 0, sizeof s->sessOrd);
                s->sessValid = false;
                SatSdls_LinkStop(SDLS_LINK_USER);
                memset(&s->sdls[SAT_TC_VC_USER1], 0, sizeof s->sdls[SAT_TC_VC_USER1]);
                snprintf(buf, sizeof buf, "ISL: user %04X handed to SAT %04X with a derived key, end to end; session key erased",
                         user, dst);
                Sat_Say(s, buf);
            }
        }
    }
    else
    {
        st = SAT_ST_UNKNOWN;
    }
    return st;
}

static void Sat_HandlePacket(Sat_Core_t *s, const uint8_t *p, int n, uint8_t vc)
{
    uint8_t        type;
    uint16_t       apid;
    uint16_t       seq;
    int            dlen;
    const uint8_t *d;
    char           buf[96];

    if (n < 7)
    {
        Sat_QueueIdle(s, vc);
        return;
    }
    type = (uint8_t)((p[0] >> 4) & 1);
    apid = (uint16_t)(((p[0] & 7) << 8) | p[1]);
    seq  = (uint16_t)(((p[2] & 0x3F) << 8) | p[3]);
    dlen = ((p[4] << 8) | p[5]) + 1;
    if ((p[0] >> 5) != 0 || type != 1 || 6 + dlen != n)
    {
        Sat_Say(s, "bad space packet");
        Sat_QueueIdle(s, vc);
        return;
    }
    d = p + 6;

    if (apid == SAT_APID_TC)
    {
        uint8_t cmd = d[0];
        uint8_t st  = SAT_ST_OK;

        if (cmd == SAT_CMD_NAK) /* any terminal may ask for its own missing chunks; no TC ACK, the chunks are the reply */
        {
            st = Sat_OnNak(s, vc, d, dlen);
            if (st == SAT_ST_OK)
            {
                s->cmdsOk++;
                return;
            }
            Sat_SendAck(s, seq, cmd, st, vc);
            return;
        }
        if (vc != SAT_TC_VC_GROUND) /* users may not command the satellite */
        {
            snprintf(buf, sizeof buf, "command on VC%u refused (not ground)", (unsigned)vc);
            Sat_Say(s, buf);
            Sat_SendAck(s, seq, cmd, SAT_ST_NOT_ALLOWED, vc);
            return;
        }
        if (cmd == SAT_CMD_FORWARD)
        {
            uint16_t dst  = dlen >= 4 ? (uint16_t)((d[1] << 8) | d[2]) : 0;
            int      next = Sat_IslRoute(s, dst, -1);
            if (dlen < 4 || next < 0 || s->islTx == NULL)
            {
                Sat_SendAck(s, seq, cmd, SAT_ST_BAD_ARG, vc);
                return;
            }
            {
                uint8_t data[4 + 64];
                int     n2 = dlen - 3;
                if (n2 > 64)
                {
                    n2 = 64;
                }
                data[0] = (uint8_t)(seq >> 8);
                data[1] = (uint8_t)seq;
                data[2] = (uint8_t)(dst >> 8);
                data[3] = (uint8_t)dst;
                memcpy(data + 4, d + 3, (size_t)n2);
                Sat_QueueIdle(s, vc);
                Sat_IslSendCtl(s, next, SAT_APID_FWDCMD, data, 4 + n2);
                s->islForwarded++;
                snprintf(buf, sizeof buf, "ISL: command 0x%02X (tc seq %u) forwarded to SAT %04X", (unsigned)d[3],
                         (unsigned)seq, dst);
                Sat_Say(s, buf);
            }
            return;
        }
        st = Sat_ExecCommand(s, cmd, d, dlen);
        if (st == SAT_ST_OK)
        {
            s->cmdsOk++;
        }
        snprintf(buf, sizeof buf, "TC seq %u cmd 0x%02X status %u", (unsigned)seq, (unsigned)cmd, (unsigned)st);
        Sat_Say(s, buf);
        Sat_SendAck(s, seq, cmd, st, vc);
        return;
    }

    if (apid == SAT_APID_RELAY && dlen >= 4)
    {
        uint16_t src  = (uint16_t)((d[0] << 8) | d[1]);
        uint16_t want = (vc == SAT_TC_VC_GROUND) ? SAT_ADDR_GS : SAT_ADDR_USER1;

        if (src != want)
        {
            snprintf(buf, sizeof buf, "relay refused: source does not match VC%u", (unsigned)vc);
            Sat_Say(s, buf);
            Sat_QueueIdle(s, vc);
            return;
        }
        s->relayed++;
        if (s->gsPeer >= 0 && ((d[2] << 8) | d[3]) == SAT_ADDR_GS)
        {
            snprintf(buf, sizeof buf, "ISL: relay %d bytes from VC%u for the ground station forwarded", dlen - 4,
                     (unsigned)vc);
            Sat_Say(s, buf);
            s->islForwarded++;
            Sat_QueueIdle(s, vc);
            Sat_IslSendPacket(s, p, n);
            return;
        }
        snprintf(buf, sizeof buf, "relay %d bytes from VC%u", dlen - 4, (unsigned)vc);
        Sat_Say(s, buf);
        /* the frame goes out under the destination's link (its own SDLS
         * association); the sender's COP-1 report is carried as a pending CLCW */
        s->clcwPending[vc] = true;
        Sat_QueueTm(s, SAT_TM_VC_RELAY, SAT_APID_RELAY, &s->relaySeq, d, dlen,
                    (((d[2] << 8) | d[3]) == SAT_ADDR_GS) ? SAT_TC_VC_GROUND : SAT_TC_VC_USER1, SAT_TURNAROUND_MS);
        return;
    }

    /* Three party authentication: src | dst | message.  The source claimed in
     * the packet must match the virtual channel it arrived on, which is the
     * cross check between a signed identity and a frame identity. */
    if (apid == SAT_APID_AUTH)
    {
        uint16_t src, dst, want;
        if (dlen < 4 + 2)
        {
            Sat_QueueIdle(s, vc);
            return;
        }
        src  = (uint16_t)((d[0] << 8) | d[1]);
        dst  = (uint16_t)((d[2] << 8) | d[3]);
        want = (vc == SAT_TC_VC_GROUND) ? SAT_ADDR_GS : SAT_ADDR_USER1;
        if (src != want || (dst != s->scid && Sat_IslRoute(s, dst, -1) < 0))
        {
            snprintf(buf, sizeof buf, "auth packet source %04X does not match VC%u, dropped", src, (unsigned)vc);
            Sat_Say(s, buf);
            Sat_QueueIdle(s, vc);
            return;
        }
        Sat_QueueIdle(s, vc); /* acknowledge the uplink segment chain through the CLCW */
        if (dst != s->scid)
        {
            /* for another satellite: the whole space packet crosses the ISL unchanged */
            snprintf(buf, sizeof buf, "ISL: auth message from %04X for SAT %04X forwarded, %d bytes", src, dst, dlen - 4);
            Sat_Say(s, buf);
            s->islForwarded++;
            Sat_IslSendPacketTo(s, Sat_IslRoute(s, dst, -1), p, n);
            return;
        }
        if (s->authRx)
        {
            s->authRx(src, d + 4, dlen - 4, Sat_NowSec(s), s->ctx);
        }
        return;
    }

    /* Any other APID is a cFS command packet: hand it to the software bus. */
    if (s->sb != NULL && vc == SAT_TC_VC_GROUND)
    {
        if (s->sb(p, n, vc, s->ctx))
        {
            s->sbPackets++;
            snprintf(buf, sizeof buf, "APID %u passed to software bus (%d bytes)", (unsigned)apid, n);
            Sat_Say(s, buf);
            Sat_QueueIdle(s, vc);
            return;
        }
    }
    snprintf(buf, sizeof buf, "unknown APID %u", (unsigned)apid);
    Sat_Say(s, buf);
    Sat_QueueIdle(s, vc);
}

void Sat_CoreInit(Sat_Core_t *s, uint16_t scid, Sat_TxFn tx, Sat_LogFn log, Sat_SbFn sb, void *ctx)
{
    int i;

    memset(s, 0, sizeof(*s));
    s->scid       = scid;
    s->tx         = tx;
    s->log        = log;
    s->sb         = sb;
    s->ctx        = ctx;
    s->hkPeriodMs = 10000u;
    s->firstHk    = true;
    for (i = 0; i < (int)SAT_TC_VC_COUNT; i++)
    {
        Sat_FarmInit(&s->farm[i]);
    }
    s->txPaceMs = SAT_TX_PACE_PCT;
    s->gsPeer   = -1;
    (void)SatSdls_Init(scid);
    s->rxWindowMs = SAT_RX_WINDOW_MS;
}

static void Sat_ReasmReset(Sat_Reasm_t *r)
{
    r->active = false;
    r->len    = 0;
}

/* One segment of a telecommand, carried in the frame data field after the
 * segment header.  COP-1 has already ordered and de-duplicated the frames, so
 * the only failures left are a segment that arrives without a first segment,
 * a telecommand that exceeds the reassembly buffer, or one that never finishes.
 */
static void Sat_OnSegment(Sat_Core_t *s, uint8_t vcid, uint8_t flags, uint8_t map, const uint8_t *d, int n)
{
    Sat_Reasm_t *r = &s->reasm[vcid];
    char         buf[96];

    if (flags == SAT_SEG_UNSEG)
    {
        Sat_ReasmReset(r);
        if (n >= 7)
        {
            Sat_HandlePacket(s, d, n, vcid);
        }
        else
        {
            Sat_QueueIdle(s, vcid);
        }
        return;
    }

    if (flags == SAT_SEG_FIRST)
    {
        Sat_ReasmReset(r);
        r->active  = true;
        r->map     = map;
        r->started = s->now;
    }
    else if (!r->active || r->map != map)
    {
        s->segErr++;
        Sat_Say(s, "continuing segment with no first segment, discarded");
        Sat_QueueIdle(s, vcid);
        return;
    }

    if (n < 0 || r->len + n > SAT_REASM_MAX)
    {
        s->segErr++;
        Sat_ReasmReset(r);
        Sat_Say(s, "telecommand exceeds the reassembly limit, discarded");
        Sat_QueueIdle(s, vcid);
        return;
    }
    memcpy(r->buf + r->len, d, (size_t)n);
    r->len += n;
    r->started = s->now; /* inactivity timeout: each segment restarts the clock */

    if (flags != SAT_SEG_LAST)
    {
        Sat_QueueIdle(s, vcid); /* report the CLCW, nothing to deliver yet */
        /* Receive window: the next segment follows the acknowledgement at once and
         * takes a full frame time on air.  The radio is half duplex, so anything
         * else transmitted in that window destroys it.  Hold housekeeping and bulk
         * downlink until it has had time to arrive; acknowledgements still go. */
        if (s->rxWindowMs)
        {
            s->rxQuietUntil = s->now + SAT_TURNAROUND_MS + Sat_AirtimeMs(32) + s->rxWindowMs;
        }
        return;
    }

    r->active = false;
    s->reasmOk++;
    snprintf(buf, sizeof buf, "reassembled %d octet telecommand on VC%u", r->len, (unsigned)vcid);
    Sat_Say(s, buf);
    if (r->len >= 7)
    {
        Sat_HandlePacket(s, r->buf, r->len, vcid);
    }
    else
    {
        Sat_QueueIdle(s, vcid);
    }
    r->len = 0;
}

void Sat_OnUplink(Sat_Core_t *s, const uint8_t *b, int n, int rssi, int snr, uint32_t now)
{
    Sat_TcFrame_t    f;
    Sat_Farm_t *     farm;
    Sat_FarmResult_t res;
    uint8_t          seg;
    char             buf[96];
    int              r;

    s->now      = now;
    s->lastRssi = (int8_t)rssi;
    s->lastSnr  = (int8_t)snr;
    s->rxFrames++;

    r = Sat_ParseTc(b, n, &f);
    if (r != SAT_TC_OK)
    {
        s->crcErr++;
        Sat_Say(s, "uplink frame rejected (format/CRC)");
        return;
    }
    if (f.scid != s->scid || f.vcid >= SAT_TC_VC_COUNT)
    {
        s->idErr++;
        Sat_Say(s, "uplink frame for another spacecraft/VC");
        return;
    }

    farm = &s->farm[f.vcid];
    res  = Sat_FarmOnFrame(farm, &f);
    if (res == SAT_FARM_DISCARD)
    {
        s->farmDiscard++;
        snprintf(buf, sizeof buf, "FARM discard VC%u N(S)=%u V(R)=%u%s", (unsigned)f.vcid, (unsigned)f.ns,
                 (unsigned)farm->vr, farm->lockout ? " LOCKOUT" : "");
        Sat_Say(s, buf);
        Sat_QueueIdle(s, f.vcid);
        return;
    }
    if (res == SAT_FARM_ACCEPT_BC)
    {
        snprintf(buf, sizeof buf, "BC accepted VC%u, V(R)=%u", (unsigned)f.vcid, (unsigned)farm->vr);
        Sat_Say(s, buf);
        Sat_QueueIdle(s, f.vcid);
        return;
    }

    /* AD or BD data frame: segment header + segment of a space packet */
    if (f.dlen < 1)
    {
        Sat_QueueIdle(s, f.vcid);
        return;
    }
    if (s->sdls[f.vcid % SAT_TC_VC_COUNT].rxActive)
    {
        /* CCSDS 355.0 receiving end: security processing follows frame acceptance
         * (FARM) and precedes segment extraction.  The frame data field is
         * segment header | SPI | IV | ciphertext | MAC. */
        static uint8_t pdu[SAT_MAX_FRAME];
        int            plen = 0;
        int32_t        r    = SatSdls_TcProcess(b, n, &seg, pdu, (int)sizeof pdu, &plen);

        if (r != 0)
        {
            s->sdlsTcRejected++;
            s->sdlsLastErr = r;
            snprintf(buf, sizeof buf, "SDLS: TC on VC%u rejected (CryptoLib %d)", (unsigned)f.vcid, (int)r);
            Sat_Say(s, buf);
            Sat_QueueIdle(s, f.vcid);
            return;
        }
        s->sdlsTcOk++;
        Sat_OnSegment(s, f.vcid, (uint8_t)(seg >> 6), (uint8_t)(seg & 0x3F), pdu, plen);
        return;
    }
    seg = f.data[0];
    Sat_OnSegment(s, f.vcid, (uint8_t)(seg >> 6), (uint8_t)(seg & 0x3F), f.data + 1, f.dlen - 1);
}

void Sat_SdlsStartLink(Sat_Core_t *s, uint8_t link, const uint8_t sk[32])
{
    int32_t r;
    char    buf[128];

    link %= SAT_TC_VC_COUNT;
    memcpy(s->sdls[link].sk, sk, 32);
    r = SatSdls_LinkRx(sk, link == SAT_TC_VC_GROUND ? SDLS_LINK_GROUND : SDLS_LINK_USER);
    if (r != 0)
    {
        s->sdlsLastErr = r;
        snprintf(buf, sizeof buf, "SDLS: receive association on TC VC%u failed to start", (unsigned)link);
        Sat_Say(s, buf);
        return;
    }
    s->sdlsStarts++;
    snprintf(buf, sizeof buf, "SDLS: %s, receive association on TC VC%u (%s link)",
             s->sdls[link].rxActive ? "rekeyed from the new session key" : "security associations started from the session key",
             (unsigned)link, link == SAT_TC_VC_GROUND ? "ground" : "user");
    Sat_Say(s, buf);
    s->sdls[link].rxActive  = true;
    s->sdls[link].pendingTx = true;
}

void Sat_SdlsStart(Sat_Core_t *s, const uint8_t sk[32])
{
    uint8_t kgl[32];

    /* the user link runs under SK; SK itself stays on this satellite */
    Sat_SdlsStartLink(s, SAT_TC_VC_USER1, sk);
    memcpy(s->sessSk, sk, 32);
    Auth_OrderKey(s->sessOrd, sk);
    s->sessValid = true;
    Auth_GroundLinkKey(kgl, sk);
    if (s->gsPeer < 0)
    {
        Sat_SdlsStartLink(s, SAT_TC_VC_GROUND, kgl);
        memset(kgl, 0, sizeof kgl);
        return;
    }
    if (s->islTx != NULL)
    {
        /* the ground station link is on another satellite: send it the ground link key end to
         * end (ML-KEM to the feeder's certificate, signed), so no relay on the way can read it */
        static uint8_t x[AUTH_XFER_LEN];
        int            n;

        if (!s->isl[s->gsPeer].secure)
        {
            Sat_Say(s, "ISL: in clear, ground link key not sent; ground link stays clear");
        }
        else if (s->xferBuild == NULL || s->feederScid == 0)
        {
            Sat_Say(s, "ISL: feeder satellite not known yet, ground link key not sent");
        }
        else if ((n = s->xferBuild(s->xferCtx, AUTH_XFER_GLINK, s->feederScid, 0, kgl, Sat_NowSec(s), x)) < 0)
        {
            Sat_Say(s, "ISL: no certificate of the feeder satellite, ground link key not sent");
        }
        else
        {
            char buf[112];
            Sat_IslSendBig(s, s->gsPeer, SAT_APID_SESSION, x, n);
            s->xferSent++;
            snprintf(buf, sizeof buf, "ISL: ground link key sent end to end to the feeder SAT %04X", s->feederScid);
            Sat_Say(s, buf);
        }
    }
    memset(kgl, 0, sizeof kgl);
}

void Sat_SdlsStop(Sat_Core_t *s)
{
    SatSdls_Stop();
    memset(s->sdls, 0, sizeof s->sdls);
    memset(s->sessSk, 0, sizeof s->sessSk);
    memset(s->sessOrd, 0, sizeof s->sessOrd);
    s->sessValid = false;
    Sat_Say(s, "SDLS: security associations stopped, link in clear");
}

void Sat_OnRadioCrcError(Sat_Core_t *s)
{
    s->crcErr++;
}

void Sat_OnRxHeartbeat(Sat_Core_t *s, uint32_t now)
{
    s->lastRxBeat = now;
}

static void Sat_DrainBigTm(Sat_Core_t *s);

void Sat_Tick(Sat_Core_t *s, uint32_t now)
{
    int  i;
    bool quiet;

    s->now = now;
    quiet = (int32_t)(s->rxQuietUntil - now) > 0;
    if (!quiet && (s->firstHk || (now - s->lastHk) >= s->hkPeriodMs))
    {
        s->firstHk = false;
        s->lastHk  = now;
        Sat_SendHk(s);
    }
    /* a satellite whose clock the ground has set shares it with its neighbour
     * every housekeeping period (time distribution over the ISL) */
    if (s->timeSet && s->islTx != NULL && s->islN > 0 && (now - s->islLastTime) >= s->hkPeriodMs)
    {
        uint8_t  data[6];
        uint32_t sec = Sat_NowSec(s);
        uint16_t fd  = s->gsPeer < 0 ? s->scid : s->feederScid; /* who holds the ground station link */

        s->islLastTime = now;
        data[0] = (uint8_t)(sec >> 24);
        data[1] = (uint8_t)(sec >> 16);
        data[2] = (uint8_t)(sec >> 8);
        data[3] = (uint8_t)sec;
        data[4] = (uint8_t)(fd >> 8);
        data[5] = (uint8_t)fd;
        for (i = 0; i < s->islN; i++)
        {
            Sat_IslSendCtl(s, i, SAT_APID_TIME, data, 6);
        }
    }
    /* abandon a telecommand whose remaining segments never arrived */
    for (i = 0; i < (int)SAT_TC_VC_COUNT; i++)
    {
        if (s->reasm[i].active && (now - s->reasm[i].started) >= SAT_REASM_TIMEOUT_MS)
        {
            s->segErr++;
            Sat_ReasmReset(&s->reasm[i]);
            Sat_Say(s, "incomplete telecommand timed out, discarded");
        }
    }
    /* a pending transmit association starts once nothing queued before it is left */
    {
        uint8_t link;
        for (link = 0; link < SAT_TC_VC_COUNT; link++)
        {
            bool relayQueued;
            if (!s->sdls[link].pendingTx)
            {
                continue;
            }
            relayQueued = s->bigActive;
            for (i = 0; i < SAT_TXQ_LEN; i++)
            {
                relayQueued = relayQueued ||
                              (s->q[i].n && (s->q[i].secure || (((s->q[i].b[1] >> 1) & 7) == SAT_TM_VC_RELAY)));
            }
            for (i = 0; i < (int)SAT_CHUNK_SLOTS; i++)
            {
                relayQueued = relayQueued || (s->chunk[i].valid && (s->chunk[i].next < s->chunk[i].total));
            }
            if (!relayQueued)
            {
                char buf[96];
                if (SatSdls_LinkTx(s->sdls[link].sk, link == SAT_TC_VC_GROUND ? SDLS_LINK_GROUND : SDLS_LINK_USER) == 0)
                {
                    s->sdls[link].txActive = true;
                    snprintf(buf, sizeof buf, "SDLS: transmit association started on TM VC%u (%s link)",
                             (unsigned)(link == SAT_TC_VC_GROUND ? SAT_TM_VC_SECURE_GS : SAT_TM_VC_SECURE),
                             link == SAT_TC_VC_GROUND ? "ground" : "user");
                }
                else
                {
                    snprintf(buf, sizeof buf, "SDLS: transmit association on %s link failed to start",
                             link == SAT_TC_VC_GROUND ? "ground" : "user");
                }
                Sat_Say(s, buf);
                s->sdls[link].pendingTx = false;
            }
        }
    }
    if (!quiet)
    {
        Sat_DrainBigTm(s);
        Sat_ChunkDrain(s);
    }
    /* transmit one queued frame whose time has come, earliest due first,
     * no sooner than txPaceMs after the previous one */
    if (s->txEver && (now - s->lastTx) < s->txHoldMs)
    {
        return;
    }
    {
        int best = -1;

        for (i = 0; i < SAT_TXQ_LEN; i++)
        {
            if (s->q[i].n && (int32_t)(now - s->q[i].due) >= 0 &&
                (best < 0 || (int32_t)(s->q[best].due - s->q[i].due) > 0))
            {
                best = i;
            }
        }
        if (best >= 0)
        {
            Sat_RefreshClcw(s, s->q[best].b, s->q[best].n);
            if (s->q[best].secure)
            {
                int32_t r = SatSdls_TmApply(s->q[best].b);

                if (r != 0)
                {
                    s->sdlsLastErr = r;
                    Sat_Say(s, "SDLS: TM apply failed, frame dropped");
                    s->q[best].n = 0;
                    return;
                }
                s->sdlsTmSent++;
            }
            if (s->tx)
            {
                s->tx(s->q[best].b, s->q[best].n, s->ctx);
            }
            s->txHoldMs  = (Sat_AirtimeMs(s->q[best].n) * s->txPaceMs) / 100u + SAT_TX_GUARD_MS;
            s->q[best].n = 0;
            s->lastTx    = now;
            s->txEver    = true;
        }
    }
}

/* Queue one TM frame carrying part or all of a packet on the relay channel.
 * Returns true when a transmit slot was available. */
static bool Sat_QueueTmChunk(Sat_Core_t *s, uint8_t vc, uint8_t clcwVc, const uint8_t *chunk, int clen, uint16_t fhp)
{
    return Sat_QueueFrame(s, vc, clcwVc, chunk, clen, fhp, 0u);
}

/* Hand a packet that does not fit one frame to the spanning transmitter. */
static bool Sat_StartSpan(Sat_Core_t *s, uint8_t vc, uint8_t clcwVc, const uint8_t *pkt, int plen)
{
    char buf[88];

    if (plen > SAT_BIGTM_MAX)
    {
        Sat_Say(s, "telemetry packet larger than the spanning limit, dropped");
        return false;
    }
    if (s->bigActive)
    {
        Sat_Say(s, "a spanned telemetry packet is already in progress, dropped");
        return false;
    }
    memcpy(s->bigTm, pkt, (size_t)plen);
    s->bigLen     = plen;
    s->bigOff     = 0;
    s->bigVc      = vc;
    s->bigClcwVc  = clcwVc;
    s->bigActive  = true;
    snprintf(buf, sizeof buf, "spanning %d octet packet across %d TM frames", plen,
             (plen + SAT_TM_DF_MAX - 1) / SAT_TM_DF_MAX);
    Sat_Say(s, buf);
    return true;
}

bool Sat_TmBusy(const Sat_Core_t *s)
{
    return s->bigActive;
}

void Sat_SetAuthRx(Sat_Core_t *s, Sat_AuthRxFn fn)
{
    s->authRx = fn;
}

uint32_t Sat_NowSec(const Sat_Core_t *s)
{
    return s->timeBaseSec + (s->now - s->timeBaseMs) / 1000u;
}

/* Downlink an auth packet payload (src | dst | message) to terminal dst. */
static void Sat_DownlinkAuth(Sat_Core_t *s, uint16_t dst, const uint8_t *data, int dlen)
{
    uint8_t clcwVc = (dst == SAT_ADDR_GS) ? SAT_TC_VC_GROUND : SAT_TC_VC_USER1;

    if (dlen + 12 <= Sat_RelayDfMax(s, clcwVc))
    {
        Sat_QueueTm(s, SAT_TM_VC_RELAY, SAT_APID_AUTH, &s->authSeq, data, dlen, clcwVc, SAT_TURNAROUND_MS);
        return;
    }
    Sat_ChunkStart(s, dst, clcwVc, data, dlen);
}

void Sat_SendAuth(Sat_Core_t *s, uint16_t dst, const uint8_t *msg, int len)
{
    static uint8_t data[4 + SAT_BIGTM_MAX];

    if (len < 0 || len + 4 + 12 > SAT_BIGTM_MAX)
    {
        Sat_Say(s, "auth message too large to send, dropped");
        return;
    }
    data[0] = (uint8_t)(s->scid >> 8);
    data[1] = (uint8_t)s->scid;
    data[2] = (uint8_t)(dst >> 8);
    data[3] = (uint8_t)dst;
    memcpy(data + 4, msg, (size_t)len);
    if (dst == SAT_ADDR_GS && s->gsPeer >= 0)
    {
        static uint8_t pkt[SAT_BIGTM_MAX];
        uint8_t        t[6];
        int            plen;
        char           buf[96];

        Sat_Cuc(s, t);
        plen = Sat_BuildPacket(pkt, 0, SAT_APID_AUTH, s->authSeq, t, 6, data, len + 4);
        s->authSeq = (uint16_t)((s->authSeq + 1) & 0x3FFF);
        snprintf(buf, sizeof buf, "ISL: auth message for the ground station sent to SAT %04X, %d bytes",
                 s->isl[s->gsPeer].scid, len);
        Sat_Say(s, buf);
        Sat_IslSendPacket(s, pkt, plen);
        return;
    }
    Sat_DownlinkAuth(s, dst, data, len + 4);
}

/* ---------------- inter satellite link ---------------- */

void Sat_SetIsl(Sat_Core_t *s, Sat_IslTxFn fn)
{
    s->islTx  = fn;
    s->islN   = 0;
    s->gsPeer = -1;
}

int Sat_AddIslPeer(Sat_Core_t *s, uint16_t peerScid, bool towardGround, const uint8_t kisl[32])
{
    char           buf[112];
    Sat_IslPeer_t *p;
    int            i;

    if (s->islN >= SAT_ISL_MAX)
    {
        Sat_Say(s, "ISL: no room for another neighbour");
        return -1;
    }
    i = s->islN++;
    p = &s->isl[i];
    memset(p, 0, sizeof *p);
    p->scid = peerScid;
    if (kisl != NULL)
    {
        int32_t r = SatSdls_IslStart(kisl, peerScid);
        if (r == 0)
        {
            p->secure = true;
        }
        else
        {
            snprintf(buf, sizeof buf, "ISL: SDLS associations toward SAT %04X failed to start (%ld)", peerScid, (long)r);
            Sat_Say(s, buf);
        }
    }
    if (towardGround)
    {
        s->gsPeer = i;
    }
    snprintf(buf, sizeof buf, "ISL: neighbour SAT %04X on TM VC%u, %s, ground station %s", peerScid,
             (unsigned)SatSdls_IslVc(s->scid, peerScid), p->secure ? "SDLS keyed from the ISL key" : "in clear",
             towardGround ? "via this neighbour" : (s->gsPeer < 0 ? "on own radio" : "via another neighbour"));
    Sat_Say(s, buf);
    return i;
}

static int Sat_IslPeerIndex(const Sat_Core_t *s, uint16_t scid)
{
    int i;

    for (i = 0; i < s->islN; i++)
    {
        if (s->isl[i].scid == scid)
        {
            return i;
        }
    }
    return -1;
}

int Sat_IslRoute(const Sat_Core_t *s, uint16_t dst, int from)
{
    int i;

    if (s->islN == 0)
    {
        return -1;
    }
    i = Sat_IslPeerIndex(s, dst);
    if (i >= 0)
    {
        return i;                       /* a direct neighbour */
    }
    if (dst == SAT_ADDR_GS)
    {
        return s->gsPeer;               /* toward the ground station, -1 when it is on our radio */
    }
    if ((dst & 0xFF00u) != 0x0100u)
    {
        return -1;                      /* a terminal other than the ground: on our radio or unknown */
    }
    /* a satellite that is not adjacent: along the chain, away from where it came from */
    for (i = 0; i < s->islN; i++)
    {
        if (i != from && (from >= 0 || i != s->gsPeer || s->islN == 1))
        {
            return i;
        }
    }
    return from >= 0 ? -1 : s->gsPeer;
}

/* One ISL frame: TM primary header | [SDLS header] | data | [MAC] | OCF | FECF.
 * data holds dlen octets of the packet stream, then an idle packet when at
 * least a packet header fits, else zero fill (the next frame's first header
 * pointer resynchronises the receiver). */
static void Sat_IslFrame(Sat_Core_t *s, int peer, const uint8_t *data, int dlen, uint16_t fhp)
{
    Sat_IslPeer_t *p = &s->isl[peer];
    uint8_t        f[SAT_MAX_FRAME];
    uint8_t        clcw[4] = {0, 0, 0, 0};
    int            dfmax = p->secure ? SAT_SDLS_TM_DF_MAX : SAT_TM_DF_MAX;
    uint8_t        df[SAT_TM_DF_MAX];
    uint8_t        vc = SatSdls_IslVc(s->scid, p->scid);
    int            left;

    memcpy(df, data, (size_t)dlen);
    left = dfmax - dlen;
    if (left >= 7)
    {
        int ilen = left - 7; /* idle packet data length minus one */
        df[dlen + 0] = 0x07;
        df[dlen + 1] = 0xFF;
        df[dlen + 2] = 0xC0;
        df[dlen + 3] = 0x00;
        df[dlen + 4] = (uint8_t)(ilen >> 8);
        df[dlen + 5] = (uint8_t)ilen;
        memset(df + dlen + 6, 0, (size_t)(left - 6));
        if (fhp == 0x7FFu)
        {
            fhp = (uint16_t)dlen;
        }
    }
    else if (left > 0)
    {
        memset(df + dlen, 0, (size_t)left);
    }
    if (p->secure)
    {
        int32_t  r;
        uint16_t dfs = (uint16_t)((3u << 11) | (fhp & 0x7FFu));
        memset(f, 0, sizeof f);
        f[0] = (uint8_t)((s->scid >> 4) & 0x3F);
        f[1] = (uint8_t)(((s->scid & 0x0F) << 4) | (vc << 1) | 0x01);
        f[2] = s->mcfc++;
        f[3] = p->vcfc++;
        f[4] = (uint8_t)(dfs >> 8);
        f[5] = (uint8_t)dfs;
        memcpy(f + 6 + 14, df, (size_t)dfmax);
        r = SatSdls_IslApply(f, p->scid);
        if (r != 0)
        {
            Sat_Say(s, "ISL: SDLS apply failed, frame not sent");
            return;
        }
        s->islFramesTx++;
        s->islTx(f, SAT_MAX_FRAME, peer, s->ctx);
        return;
    }
    (void)Sat_BuildTm(f, s->scid, vc, s->mcfc++, p->vcfc++, df, dfmax, clcw, fhp);
    s->islFramesTx++;
    s->islTx(f, SAT_MAX_FRAME, peer, s->ctx);
}

void Sat_IslSendPacketTo(Sat_Core_t *s, int peer, const uint8_t *pkt, int plen)
{
    int dfmax, off = 0;

    if (s->islTx == NULL || peer < 0 || peer >= s->islN)
    {
        Sat_Say(s, "ISL: no route, packet dropped");
        return;
    }
    dfmax = s->isl[peer].secure ? SAT_SDLS_TM_DF_MAX : SAT_TM_DF_MAX;
    while (off < plen)
    {
        int n = plen - off;
        if (n > dfmax)
        {
            n = dfmax;
        }
        Sat_IslFrame(s, peer, pkt + off, n, off == 0 ? 0u : 0x7FFu);
        off += n;
    }
}

void Sat_IslSendPacket(Sat_Core_t *s, const uint8_t *pkt, int plen)
{
    Sat_IslSendPacketTo(s, s->gsPeer, pkt, plen);
}

/* Build a small ISL control packet and send it to peer. */
static void Sat_IslSendCtl(Sat_Core_t *s, int peer, uint16_t apid, const uint8_t *data, int dlen)
{
    uint8_t pkt[96];
    uint8_t t[6];
    int     plen;

    if (dlen > 80)
    {
        return;
    }
    Sat_Cuc(s, t);
    plen = Sat_BuildPacket(pkt, 0, apid, s->authSeq, t, 6, data, dlen);
    s->authSeq = (uint16_t)((s->authSeq + 1) & 0x3FFF);
    Sat_IslSendPacketTo(s, peer, pkt, plen);
    memset(pkt, 0, sizeof pkt);
}

/* A control packet too large for Sat_IslSendCtl: a key transfer of about 4.5 kB, spanned across
 * ISL frames like any other space packet. */
static void Sat_IslSendBig(Sat_Core_t *s, int peer, uint16_t apid, const uint8_t *data, int dlen)
{
    static uint8_t pkt[AUTH_XFER_LEN + 32];
    uint8_t        t[6];
    int            plen;

    if (dlen > AUTH_XFER_LEN)
    {
        return;
    }
    Sat_Cuc(s, t);
    plen = Sat_BuildPacket(pkt, 0, apid, s->authSeq, t, 6, data, dlen);
    s->authSeq = (uint16_t)((s->authSeq + 1) & 0x3FFF);
    Sat_IslSendPacketTo(s, peer, pkt, plen);
}

/* A complete space packet arrived over the ISL from neighbour `from`: route it. */
static void Sat_IslOnPacket(Sat_Core_t *s, int from, const uint8_t *p, int n)
{
    uint16_t       apid = (uint16_t)(((p[0] & 0x07) << 8) | p[1]);
    int            hdr  = (p[0] & 0x08) ? 12 : 6; /* telemetry carries a CUC secondary header, telecommands none */
    const uint8_t *d    = p + hdr;
    int            dlen = n - hdr;
    uint16_t       fromScid = s->isl[from].scid;
    bool           secure   = s->isl[from].secure;
    char           buf[112];
    int            next;

    s->islPacketsRx++;
    if (dlen < 4)
    {
        return;
    }
    if (apid == SAT_APID_TIME)
    {
        if (dlen == 6 && secure && s->gsPeer >= 0 && from == s->gsPeer)
        {
            uint16_t fd = (uint16_t)((d[4] << 8) | d[5]);
            if (fd != 0 && fd != s->feederScid)
            {
                s->feederScid = fd;
                snprintf(buf, sizeof buf, "ISL: the feeder is SAT %04X", fd);
                Sat_Say(s, buf);
            }
        }
        if (!s->timeSet && dlen >= 4)
        {
            s->timeBaseSec = ((uint32_t)d[0] << 24) | ((uint32_t)d[1] << 16) | ((uint32_t)d[2] << 8) | d[3];
            s->timeBaseMs  = s->now;
            s->timeSet     = true;
            snprintf(buf, sizeof buf, "ISL: clock set from SAT %04X (%lu)", fromScid, (unsigned long)s->timeBaseSec);
            Sat_Say(s, buf);
        }
        return;
    }
    if (apid == SAT_APID_FWDCMD)
    {
        /* tc seq 2 | destination SCID 2 | cmd | args: for us, or on along the chain */
        uint16_t seq = (uint16_t)((d[0] << 8) | d[1]);
        uint16_t dst = (uint16_t)((d[2] << 8) | d[3]);
        uint8_t  ack[4];
        uint8_t  st;

        if (dst != s->scid)
        {
            next = Sat_IslRoute(s, dst, from);
            if (next >= 0)
            {
                s->islForwarded++;
                Sat_IslSendPacketTo(s, next, p, n);
            }
            return;
        }
        st = secure ? Sat_ExecCommand(s, d[4], d + 4, dlen - 4) : SAT_ST_NOT_ALLOWED;
        if (st == SAT_ST_OK)
        {
            s->cmdsOk++;
        }
        snprintf(buf, sizeof buf, "ISL: forwarded command 0x%02X (tc seq %u) executed, status %u", (unsigned)d[4],
                 (unsigned)seq, (unsigned)st);
        Sat_Say(s, buf);
        ack[0] = d[0];
        ack[1] = d[1];
        ack[2] = d[4];
        ack[3] = st;
        Sat_IslSendCtl(s, s->gsPeer >= 0 ? s->gsPeer : from, SAT_APID_FWDACK, ack, 4);
        return;
    }
    if (apid == SAT_APID_FWDACK)
    {
        /* toward the ground station: down if it is ours, else on */
        if (s->gsPeer >= 0)
        {
            s->islForwarded++;
            Sat_IslSendPacketTo(s, s->gsPeer, p, n);
        }
        else if (dlen >= 4)
        {
            Sat_QueueTm(s, SAT_TM_VC_HK, SAT_APID_TC_ACK, &s->ackSeq, d, 4, SAT_TC_VC_GROUND, 0u);
        }
        return;
    }
    if (apid == SAT_APID_USERSESS || apid == SAT_APID_SESSION)
    {
        /* End to end key transfer (see sat_auth.h): USERSESS carries the next link key of a
         * user to the satellite that takes the user over, SESSION carries the ground link key
         * to the feeder.  A satellite that is not the destination forwards the packet and
         * cannot open it. */
        const bool usersess = (apid == SAT_APID_USERSESS);
        uint16_t   dst      = dlen >= AUTH_XFER_HDR ? (uint16_t)((d[3] << 8) | d[4]) : 0;
        uint16_t   src = 0, user = 0;
        uint8_t    key[32];
        int        r;

        if (!secure || dlen != AUTH_XFER_LEN)
        {
            s->islRejected++;
            return;
        }
        if (dst != s->scid)
        {
            next = usersess ? Sat_IslRoute(s, dst, from) : s->gsPeer;
            if (next >= 0 && next != from && s->isl[next].secure)
            {
                s->islForwarded++;
                Sat_IslSendPacketTo(s, next, p, n);
            }
            return;
        }
        r = s->xferOpen == NULL ? -9
                                : s->xferOpen(s->xferCtx, d, dlen, usersess ? AUTH_XFER_USERSESS : AUTH_XFER_GLINK,
                                              Sat_NowSec(s), &src, &user, key);
        if (r != 0)
        {
            s->xferRejected++;
            snprintf(buf, sizeof buf, "ISL: key transfer rejected (%s)",
                     r == -2 ? "sender is not a known satellite" : r == -3 ? "signature" : r == -4 ? "stale" :
                     r == -5 ? "wrap" : r == -6 ? "replayed" : "malformed");
            Sat_Say(s, buf);
            return;
        }
        s->xferAccepted++;
        if (usersess)
        {
            snprintf(buf, sizeof buf, "ISL: user %04X taken over from SAT %04X, keying the user link (handover)", user,
                     src);
            Sat_Say(s, buf);
            Sat_SdlsStartLink(s, SAT_TC_VC_USER1, key);
            memcpy(s->sessSk, key, 32);
            Auth_OrderKey(s->sessOrd, key);
            s->sessValid = true;
        }
        else if (s->gsPeer < 0)
        {
            snprintf(buf, sizeof buf, "ISL: ground link key received from SAT %04X, keying the ground station link", src);
            Sat_Say(s, buf);
            Sat_SdlsStartLink(s, SAT_TC_VC_GROUND, key);
        }
        memset(key, 0, sizeof key);
        return;
    }
    if (apid == SAT_APID_AUTH || apid == SAT_APID_RELAY)
    {
        uint16_t src = (uint16_t)((d[0] << 8) | d[1]);
        uint16_t dst = (uint16_t)((d[2] << 8) | d[3]);

        if (apid == SAT_APID_AUTH && dst == s->scid)
        {
            snprintf(buf, sizeof buf, "ISL: auth message from %04X for this satellite, %d bytes", src, dlen - 4);
            Sat_Say(s, buf);
            if (s->authRx)
            {
                s->authRx(src, d + 4, dlen - 4, Sat_NowSec(s), s->ctx);
            }
            return;
        }
        next = Sat_IslRoute(s, dst, from);
        if (next >= 0)
        {
            snprintf(buf, sizeof buf, "ISL: %s from %04X for %04X passed on to SAT %04X",
                     apid == SAT_APID_AUTH ? "auth message" : "relay", src, dst, s->isl[next].scid);
            Sat_Say(s, buf);
            s->islForwarded++;
            Sat_IslSendPacketTo(s, next, p, n);
            return;
        }
        if ((dst & 0xFF00u) == 0x0100u)
        {
            s->islRejected++;
            return;                     /* a satellite we cannot reach */
        }
        s->islForwarded++;
        if (apid == SAT_APID_AUTH)
        {
            snprintf(buf, sizeof buf, "ISL: auth message from %04X for terminal %04X, %d bytes, downlinked", src, dst,
                     dlen - 4);
            Sat_Say(s, buf);
            Sat_DownlinkAuth(s, dst, d, dlen);
        }
        else
        {
            snprintf(buf, sizeof buf, "ISL: relay %d bytes for terminal %04X, downlinked", dlen - 4, dst);
            Sat_Say(s, buf);
            Sat_QueueTm(s, SAT_TM_VC_RELAY, SAT_APID_RELAY, &s->relaySeq, d, dlen,
                        dst == SAT_ADDR_GS ? SAT_TC_VC_GROUND : SAT_TC_VC_USER1, SAT_TURNAROUND_MS);
        }
        return;
    }
    snprintf(buf, sizeof buf, "ISL: APID %u not routed", (unsigned)apid);
    Sat_Say(s, buf);
}

void Sat_OnIsl(Sat_Core_t *s, const uint8_t *frame, int n, uint32_t now)
{
    uint8_t        data[SAT_TM_DF_MAX];
    int            dlen, peer;
    uint16_t       fhp, scid;
    uint8_t        vc;
    const uint8_t *q;
    Sat_IslPeer_t *p;

    s->now = now;
    if (n != SAT_MAX_FRAME || frame[0] & 0xC0)
    {
        s->islRejected++;
        return;
    }
    scid = (uint16_t)(((frame[0] & 0x3F) << 4) | (frame[1] >> 4));
    vc   = (uint8_t)((frame[1] >> 1) & 7);
    peer = Sat_IslPeerIndex(s, scid);
    if (peer < 0 || vc != SatSdls_IslVc(scid, s->scid))
    {
        s->islRejected++;
        return;
    }
    p   = &s->isl[peer];
    fhp = (uint16_t)(((frame[4] & 0x07) << 8) | frame[5]);
    if (p->secure)
    {
        int32_t r = SatSdls_TmProcess(frame, n, data, sizeof data, &dlen);
        if (r != 0)
        {
            char buf[80];
            s->islRejected++;
            snprintf(buf, sizeof buf, "ISL: frame from SAT %04X rejected by SDLS (%ld)", scid, (long)r);
            Sat_Say(s, buf);
            return;
        }
    }
    else
    {
        if (Sat_Crc16(frame, n - 2) != (uint16_t)((frame[n - 2] << 8) | frame[n - 1]))
        {
            s->islRejected++;
            return;
        }
        dlen = n - 6 - 4 - 2;
        memcpy(data, frame + 6, (size_t)dlen);
    }
    s->islFramesRx++;

    /* packet stream reassembly, CCSDS 132.0 first header pointer */
    if (fhp != 0x7FFu)
    {
        int need = -1;
        if (p->rxLen >= 6)
        {
            need = 6 + (((p->rx[4] << 8) | p->rx[5]) + 1) - p->rxLen;
        }
        if (need != (int)fhp)
        {
            p->rxLen = 0;            /* not a continuation: resynchronise at the pointer */
            q = data + fhp;
            dlen -= fhp;
            memcpy(p->rx, q, (size_t)dlen);
            p->rxLen = dlen;
            goto parse;
        }
    }
    else if (p->rxLen == 0)
    {
        return;                      /* nothing pending and no header here */
    }
    if (p->rxLen + dlen > (int)sizeof p->rx)
    {
        p->rxLen = 0;
        return;
    }
    memcpy(p->rx + p->rxLen, data, (size_t)dlen);
    p->rxLen += dlen;
parse:
    for (;;)
    {
        int plen, apid;
        if (p->rxLen < 6)
        {
            break;
        }
        plen = 6 + (((p->rx[4] << 8) | p->rx[5]) + 1);
        apid = ((p->rx[0] & 0x07) << 8) | p->rx[1];
        if (plen > SAT_REASM_MAX)
        {
            p->rxLen = 0;
            break;
        }
        if (p->rxLen < plen)
        {
            break;
        }
        if (apid != (int)SAT_APID_IDLE)
        {
            Sat_IslOnPacket(s, peer, p->rx, plen);
        }
        memmove(p->rx, p->rx + plen, (size_t)(p->rxLen - plen));
        p->rxLen -= plen;
        if (apid == (int)SAT_APID_IDLE)
        {
            p->rxLen = 0;            /* an idle packet ends the frame's content */
            break;
        }
    }
    if (p->rxLen < 6 && p->rxLen > 0 && fhp != 0x7FFu)
    {
        /* a header is never split across frames: trailing bytes are fill */
        p->rxLen = 0;
    }
}

/* Begin the chunked transmission of a large message to dst.  The copy is
 * retained for selective retransmission until the next message to the same
 * destination replaces it. */
static void Sat_ChunkStart(Sat_Core_t *s, uint16_t dst, uint8_t clcwVc, const uint8_t *data, int len)
{
    Sat_ChunkOut_t *o = &s->chunk[clcwVc % SAT_CHUNK_SLOTS];
    char            buf[96];

    memset(o, 0, sizeof *o);
    memcpy(o->buf, data, (size_t)len);
    o->len      = len;
    o->dst      = dst;
    o->clcwVc   = clcwVc;
    o->csize    = s->sdls[clcwVc % SAT_TC_VC_COUNT].txActive ? SAT_SDLS_CHUNK_MAX : SAT_CHUNK_MAX;
    o->total    = (uint16_t)((len + o->csize - 1) / o->csize);
    o->firstSeq = s->authSeq;
    o->next     = 0;
    o->valid    = true;
    s->authSeq  = (uint16_t)((s->authSeq + o->total) & 0x3FFF);
    snprintf(buf, sizeof buf, "chunking %d octet message to 0x%04X into %u packets from seq %u", len,
             (unsigned)dst, (unsigned)o->total, (unsigned)o->firstSeq);
    Sat_Say(s, buf);
}

/* Queue chunk idx of a retained message as one APID 700 packet in one frame. */
static bool Sat_ChunkQueue(Sat_Core_t *s, Sat_ChunkOut_t *o, uint16_t idx)
{
    uint8_t  pkt[SAT_TM_DF_MAX];
    uint8_t  d[SAT_CHUNK_HDR + SAT_CHUNK_MAX];
    uint8_t  t[6];
    uint8_t  flags;
    int      off  = (int)idx * o->csize;
    int      clen = o->len - off;
    int      plen;

    if (clen > o->csize)
    {
        clen = o->csize;
    }
    d[0] = (uint8_t)(o->dst >> 8);
    d[1] = (uint8_t)o->dst;
    d[2] = (uint8_t)(o->total >> 8);
    d[3] = (uint8_t)o->total;
    d[4] = (uint8_t)(idx >> 8);
    d[5] = (uint8_t)idx;
    memcpy(d + SAT_CHUNK_HDR, o->buf + off, (size_t)clen);
    flags = (idx == 0) ? SAT_SEQF_FIRST : ((idx + 1 == o->total) ? SAT_SEQF_LAST : SAT_SEQF_CONT);
    Sat_Cuc(s, t);
    plen   = Sat_BuildPacketF(pkt, 0, SAT_APID_AUTH, (uint16_t)((o->firstSeq + idx) & 0x3FFF), flags, t, 6, d,
                              SAT_CHUNK_HDR + clen);
    return Sat_QueueFrame(s, SAT_TM_VC_RELAY, o->clcwVc, pkt, plen, 0u, 0u);
}

/* One chunk per call, retransmissions first, then the initial sequence.  Keeps
 * two transmit slots free for acknowledgements and housekeeping. */
static void Sat_ChunkDrain(Sat_Core_t *s)
{
    int      used = 0;
    int      i;
    unsigned k;

    for (i = 0; i < SAT_TXQ_LEN; i++)
    {
        used += (s->q[i].n != 0);
    }
    if (used >= SAT_TXQ_LEN - 2)
    {
        return;
    }
    for (k = 0; k < SAT_CHUNK_SLOTS; k++)
    {
        Sat_ChunkOut_t *o = &s->chunk[k];
        uint16_t        idx;

        if (!o->valid)
        {
            continue;
        }
        if (o->retxCount)
        {
            for (idx = 0; idx < o->total; idx++)
            {
                if (o->retx[idx / 8] & (uint8_t)(1u << (idx % 8)))
                {
                    if (Sat_ChunkQueue(s, o, idx))
                    {
                        o->retx[idx / 8] &= (uint8_t)~(1u << (idx % 8));
                        o->retxCount--;
                        s->chunksRetx++;
                    }
                    return;
                }
            }
        }
        if (o->next < o->total)
        {
            if (Sat_ChunkQueue(s, o, o->next))
            {
                o->next++;
            }
            return;
        }
    }
}

/* SAT_CMD_NAK from the VC's own terminal: mark the listed chunks of the message
 * retained for that VC for retransmission. */
static uint8_t Sat_OnNak(Sat_Core_t *s, uint8_t vc, const uint8_t *d, int dlen)
{
    Sat_ChunkOut_t *o = &s->chunk[vc % SAT_CHUNK_SLOTS];
    uint16_t        firstSeq;
    uint8_t         n;
    int             i;
    char            buf[96];

    if (dlen < 4)
    {
        return SAT_ST_BAD_ARG;
    }
    firstSeq = (uint16_t)(((uint16_t)d[1] << 8) | d[2]);
    n        = d[3];
    if (dlen != 4 + 2 * (int)n)
    {
        return SAT_ST_BAD_ARG;
    }
    s->naksRx++;
    if (!o->valid || o->firstSeq != firstSeq)
    {
        Sat_Say(s, "NAK for a message no longer retained");
        return SAT_ST_BAD_ARG;
    }
    for (i = 0; i < (int)n; i++)
    {
        uint16_t idx = (uint16_t)(((uint16_t)d[4 + 2 * i] << 8) | d[5 + 2 * i]);

        /* a chunk the initial pass has not reached yet will come anyway */
        if (idx < o->total && idx < o->next && !(o->retx[idx / 8] & (uint8_t)(1u << (idx % 8))))
        {
            o->retx[idx / 8] |= (uint8_t)(1u << (idx % 8));
            o->retxCount++;
        }
    }
    snprintf(buf, sizeof buf, "NAK on VC%u: %u chunks of message seq %u to retransmit", (unsigned)vc, (unsigned)n,
             (unsigned)firstSeq);
    Sat_Say(s, buf);
    return SAT_ST_OK;
}

void Sat_SendTlmPacket(Sat_Core_t *s, const uint8_t *packet, int len, uint32_t now)
{
    s->now = now;
    if (len <= 0)
    {
        return;
    }
    if (len <= Sat_RelayDfMax(s, SAT_TC_VC_GROUND))
    {
        if (!Sat_QueueTmChunk(s, SAT_TM_VC_RELAY, SAT_TC_VC_GROUND, packet, len, 0u))
        {
            Sat_Say(s, "TX queue full, telemetry dropped");
        }
        return;
    }
    (void)Sat_StartSpan(s, SAT_TM_VC_RELAY, SAT_TC_VC_GROUND, packet, len);
}

/* Emit the next piece of a spanned telemetry packet, if a slot is free. */
static void Sat_DrainBigTm(Sat_Core_t *s)
{
    int      clen;
    uint16_t fhp;

    int      used = 0;
    int      i;

    if (!s->bigActive)
    {
        return;
    }
    /* keep two slots free for acknowledgements and housekeeping */
    for (i = 0; i < SAT_TXQ_LEN; i++)
    {
        used += (s->q[i].n != 0);
    }
    if (used >= SAT_TXQ_LEN - 2)
    {
        return;
    }
    clen = s->bigLen - s->bigOff;
    if (clen > (s->bigVc == SAT_TM_VC_RELAY ? Sat_RelayDfMax(s, s->bigClcwVc) : SAT_TM_DF_MAX))
    {
        clen = (s->bigVc == SAT_TM_VC_RELAY ? Sat_RelayDfMax(s, s->bigClcwVc) : SAT_TM_DF_MAX);
    }
    /* the first frame carries the start of the packet, the rest only continue it */
    fhp = (s->bigOff == 0) ? 0u : (uint16_t)SAT_FHP_NONE;
    if (!Sat_QueueTmChunk(s, s->bigVc, s->bigClcwVc, s->bigTm + s->bigOff, clen, fhp))
    {
        return; /* no slot free, try again on the next tick */
    }
    s->bigOff += clen;
    if (s->bigOff >= s->bigLen)
    {
        s->bigActive = false;
        s->bigLen    = 0;
        s->bigOff    = 0;
    }
}
