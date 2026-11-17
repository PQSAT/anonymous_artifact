/* sat_ccsds.h  -  CCSDS satellite link core, C version (for the cFS sat_rf app).
 *
 * This is a direct C port of ccsds_core.h used on the T-Beam satellite, so the
 * ground station (ccsds_link.py) and user terminal talk to the Versal satellite
 * exactly as before.  The ICD is unchanged.
 *
 * Standards:
 *   CCSDS 133.0-B  Space Packet Protocol
 *   CCSDS 232.0-B  TC Space Data Link Protocol (TC frame, segment header, FECF)
 *   CCSDS 232.1-B  COP-1: FARM-1 on board, CLCW reported in the TM OCF
 *   CCSDS 132.0-B  TM Space Data Link Protocol (TM frame, OCF, FECF)
 *   CCSDS 301.0-B  Time Code Formats: CUC, 4 coarse + 2 fine octets
 * Testbed deviation (in the ICD): TM frames are variable length because LoRa
 * already delimits each frame; one space packet per TM frame (FHP = 0).
 */
#ifndef SAT_CCSDS_H
#define SAT_CCSDS_H

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ---------------- identifiers (ICD) ---------------- */
#define SAT_SCID_SAT1 0x101u /* spacecraft ID, 10 bits */

#define SAT_TC_VC_GROUND 0u /* TC virtual channel used by the ground station */
#define SAT_TC_VC_USER1  1u /* TC virtual channel used by user 1 */
#define SAT_TC_VC_COUNT  2u

#define SAT_TM_VC_HK    0u /* TM VC: telemetry, ACKs, COP-1 status */
#define SAT_TM_VC_RELAY 1u /* TM VC: relayed messages, in clear */
#define SAT_TM_VC_SECURE 2u /* TM VC: relayed messages under SDLS, fixed length frames */
#define SAT_TM_VC_ISL    3u /* inter satellite link toward the neighbour with the lower SCID (TM frames, own SCID) */
#define SAT_TM_VC_ISL_UP 5u /* inter satellite link toward the neighbour with the higher SCID */
#define SAT_ISL_MAX      2  /* neighbours per satellite: a chain */
#define SAT_TM_VC_SECURE_GS 4u /* TM VC: messages to the ground station under SDLS (the ground link's own association) */

#define SAT_APID_HK     100u
#define SAT_APID_TC     500u
#define SAT_APID_TC_ACK 501u
#define SAT_APID_RELAY  600u
#define SAT_APID_AUTH   700u /* three party authentication, data = src 2 | dst 2 | message */
#define SAT_APID_SESSION 701u /* ISL only: session key handed from the serving satellite to the feeder satellite */
#define SAT_APID_TIME    702u /* ISL only: spacecraft time shared with the neighbour (CUC, as SET_TIME) */
#define SAT_APID_FWDCMD  703u /* ISL only: command forwarded on the ground's behalf: tc seq 2 | cmd | args */
#define SAT_APID_FWDACK  704u /* ISL only: its acknowledgement: tc seq 2 | cmd | status */
#define SAT_APID_USERSESS 705u /* ISL only: hand over, end to end transfer of the next link key (sat_auth.h) */
#define SAT_APID_IDLE   0x7FFu

#define SAT_CMD_PING        0x01u
#define SAT_CMD_SET_HK_RATE 0x02u /* uint16 seconds, 2..60 */
#define SAT_CMD_SET_TIME    0x03u /* uint32 seconds since 1970-01-01 */
#define SAT_CMD_SA_STOP     0x0Bu /* ground only, no arguments: stop the SDLS security associations (CCSDS 355.1 Stop SA) */
#define SAT_CMD_FORWARD     0x0Cu /* ground only: uint16 destination SCID, then a command (cmd octet and arguments)
                                     for the neighbour, carried over the ISL; the neighbour's acknowledgement comes
                                     back over the ISL and is downlinked with the original sequence count */
#define SAT_CMD_HANDOVER    0x0Du /* ground only, executed on the serving satellite (usually forwarded): uint16 user
                                     identity, uint16 target SCID: hand the user's session key to the target over
                                     the protected ISL so the user continues under SDLS after retuning */
#define SAT_CMD_NAK         0x0Au /* uint16 first packet sequence count, uint8 n, n x uint16 chunk index:
                                     selective retransmission request for a chunked downlink message.
                                     Accepted on any TC VC; applies to the message retained for that VC. */


#define SAT_ST_OK          0u
#define SAT_ST_BAD_ARG     1u
#define SAT_ST_UNKNOWN     2u
#define SAT_ST_NOT_ALLOWED 3u

#define SAT_ADDR_GS    0x0001u
#define SAT_ADDR_USER1 0x0011u
#define SAT_ADDR_USER2 0x0012u

#define SAT_MAX_FRAME 255 /* LoRa payload limit */
#define SAT_TXQ_LEN   8
#define SAT_TURNAROUND_MS 80u /* lets the ground radio turn round before we answer */
/* Transmit pacing.  After each frame the next one waits for that frame's air
 * time (LoRa SF9, 125 kHz, 4/7, explicit header, CRC: 1.72 s for a full frame,
 * 0.3 s for an idle frame) plus a guard.  Pacing keeps the modem queue shallow
 * so an acknowledgement is not buried behind bulk downlink, and leaves receive
 * windows on a half duplex radio.  txPaceMs scales the air time in percent,
 * 100 = real time; 0 disables pacing. */
#define SAT_TX_PACE_PCT 100u
#define SAT_TX_GUARD_MS 60u
#ifndef SAT_LORA_SF
#define SAT_LORA_SF 9u
#endif
#define SAT_LORA_BW_HZ 125000u
#define SAT_LORA_CR 3u
#define SAT_LORA_PREAMBLE 8u
uint32_t Sat_AirtimeMs(int nbytes);
void     Sat_SetLoraSf(unsigned sf); /* 7 to 12; SAT_LORA_SF in the environment sets it at start */
/* Receive window held open after acknowledging a segment of a segmented
 * telecommand: one full frame on air plus margin for the terminal's turnaround
 * and serial path (measured 0.1 to 0.5 s).  0 disables. */
#define SAT_RX_WINDOW_MS (1717u + 800u)
int Sat_BuildPacketF(uint8_t *out, uint8_t type, uint16_t apid, uint16_t seq, uint8_t seqFlags,
                     const uint8_t *shdr, int shlen, const uint8_t *d, int dlen);

/* ---------------- segmentation (CCSDS 232.0 segment header) ----------------
 * Segment header octet = sequence flags (2 bits) | MAP identifier (6 bits).
 * A telecommand larger than one frame is carried as first, zero or more
 * continuing, then last segments on the same virtual channel.  COP-1 already
 * guarantees they arrive in order and without gaps, so reassembly is a simple
 * append with a size limit and a timeout.
 */
#define SAT_SEG_CONT   0u /* 00 continuing segment  */
#define SAT_SEG_FIRST  1u /* 01 first segment       */
#define SAT_SEG_LAST   2u /* 10 last segment        */
#define SAT_SEG_UNSEG  3u /* 11 unsegmented         */
#define SAT_MAP_DEFAULT 0u

/* Frame data field capacities, derived from the 255 octet radio payload:
 *   TC  5 header + 1 segment header + data + 2 FECF
 *   TM  6 header + data + 4 OCF + 2 FECF
 */
#define SAT_TC_SEG_MAX 247
#define SAT_TM_DF_MAX  243

/* First header pointer values defined by CCSDS 132.0 */
#define SAT_FHP_NONE 0x7FFu /* no packet starts in this frame (continuation) */
#define SAT_FHP_IDLE 0x7FEu /* frame contains only idle data                */

#define SAT_REASM_MAX     32768 /* largest telecommand we will reassemble */
#define SAT_BIGTM_MAX     32768 /* largest telemetry packet we will send  */
#define SAT_REASM_TIMEOUT_MS 30000u

/* ---------------- framing helpers ---------------- */
uint16_t Sat_Crc16(const uint8_t *d, int n);

typedef struct
{
    bool           bypass;
    bool           ctrl;
    uint16_t       scid;
    uint8_t        vcid;
    uint8_t        ns;
    const uint8_t *data; /* frame data field */
    int            dlen;
} Sat_TcFrame_t;

enum
{
    SAT_TC_OK = 0,
    SAT_TC_SHORT = -1,
    SAT_TC_VERSION = -2,
    SAT_TC_LENGTH = -3,
    SAT_TC_CRC = -4
};

int Sat_ParseTc(const uint8_t *b, int n, Sat_TcFrame_t *f);

/* Build one TM transfer frame.  fhp is the first header pointer: 0 when a
 * packet starts at the beginning of the data field, SAT_FHP_NONE when this
 * frame only continues a packet started earlier, SAT_FHP_IDLE for idle data. */
int Sat_BuildTm(uint8_t *out, uint16_t scid, uint8_t vcid, uint8_t mcfc, uint8_t vcfc, const uint8_t *pkt, int plen,
                const uint8_t clcw[4], uint16_t fhp);

int Sat_BuildPacket(uint8_t *out, uint8_t type, uint16_t apid, uint16_t seq, const uint8_t *shdr, int shlen,
                    const uint8_t *d, int dlen);

/* ---------------- FARM-1 (COP-1 receiver) ---------------- */
typedef struct
{
    uint8_t vr;     /* V(R): next expected N(S) */
    bool    lockout;
    bool    wait;
    bool    retransmit;
    uint8_t farmB;  /* FARM-B counter, 2 bits */
    uint8_t window; /* FARM sliding window width W */
} Sat_Farm_t;

typedef enum
{
    SAT_FARM_DISCARD = 0,
    SAT_FARM_ACCEPT_AD = 1,
    SAT_FARM_ACCEPT_BC = 2,
    SAT_FARM_ACCEPT_BD = 3
} Sat_FarmResult_t;

void             Sat_FarmInit(Sat_Farm_t *farm);
Sat_FarmResult_t Sat_FarmOnFrame(Sat_Farm_t *farm, const Sat_TcFrame_t *f);
void             Sat_FarmClcw(const Sat_Farm_t *farm, uint8_t vcid, uint8_t out[4]);

/* ---------------- the satellite ---------------- */
struct Sat_Core;
/* End to end key transfer between satellites, provided by the authentication module
 * (Auth_XferBuild and Auth_XferOpen with this satellite's keys and the peer certificates). */
typedef int (*Sat_XferBuildFn)(void *ctx, uint8_t label, uint16_t dst, uint16_t user, const uint8_t key[32],
                               uint32_t now_s, uint8_t *out);
typedef int (*Sat_XferOpenFn)(void *ctx, const uint8_t *in, int len, uint8_t label, uint32_t now_s, uint16_t *src,
                              uint16_t *user, uint8_t key[32]);

/* Transmit one downlink frame (the app writes it to the radio link). */
typedef void (*Sat_TxFn)(const uint8_t *frame, int n, void *ctx);
/* Log one line. */
typedef void (*Sat_LogFn)(const char *msg, void *ctx);
/* A space packet whose APID is not part of the ICD: hand it to the cFS software
 * bus.  Return true if it was accepted.  May be NULL. */
typedef bool (*Sat_SbFn)(const uint8_t *packet, int len, uint8_t tcVc, void *ctx);
/* An authentication message arrived from `src` (already checked against the
 * virtual channel it came on).  May be NULL. */
typedef void (*Sat_AuthRxFn)(uint16_t src, const uint8_t *msg, int len, uint32_t nowSec, void *ctx);

/* Transmit one frame on the inter satellite link to neighbour `peer` (index
 * into the peer table; a reliable local link: socket on the Versal, pipe in
 * the emulator).  May be NULL: no ISL. */
typedef void (*Sat_IslTxFn)(const uint8_t *frame, int n, int peer, void *ctx);

typedef struct
{
    uint16_t scid;      /* neighbour's SCID */
    bool     secure;    /* SDLS keyed on this link */
    uint8_t  vcfc;
    uint8_t  rx[SAT_REASM_MAX + SAT_MAX_FRAME]; /* packet stream reassembly */
    int      rxLen;
} Sat_IslPeer_t;

typedef struct
{
    uint8_t  b[SAT_MAX_FRAME];
    int      n;
    uint32_t due;
    bool     secure; /* TM VC2: SDLS applied at transmit time */
} Sat_TxSlot_t;

/* SDLS (CCSDS 355.0) by NASA CryptoLib, see sat_sdls.h.  Protected TM frames
 * are fixed length: header 6 | SPI 2 | IV 12 | data | MAC 16 | OCF 4 | FECF 2. */
#define SAT_SDLS_TM_DF_MAX (SAT_MAX_FRAME - 6 - 14 - 16 - 4 - 2) /* 213 */
#define SAT_SDLS_CHUNK_MAX (SAT_SDLS_TM_DF_MAX - 12 - 6)         /* 195 */

/* Chunked downlink (CCSDS 133.0 packet segmentation).  A message larger than
 * one frame goes out as a sequence of APID 700 packets, one per TM frame, with
 * sequence flags first/continuation/last and consecutive sequence counts.  Each
 * carries a 6 octet chunk header: destination, total chunks, chunk index.  The
 * message is retained so the receiver can ask for missing chunks by index
 * (SAT_CMD_NAK), in the manner of CFDP class 2 deferred NAK.  TM frames carry
 * no retransmission of their own. */
#define SAT_CHUNK_HDR 6
#define SAT_CHUNK_MAX (SAT_TM_DF_MAX - 12 - SAT_CHUNK_HDR) /* 225 octets of message per frame */
#define SAT_CHUNK_SLOTS 2u                                 /* one retained message per destination */
#define SAT_CHUNK_BITMAP ((SAT_BIGTM_MAX / SAT_CHUNK_MAX + 8) / 8)
#define SAT_SEQF_CONT  0x00u
#define SAT_SEQF_FIRST 0x01u
#define SAT_SEQF_LAST  0x02u
#define SAT_SEQF_UNSEG 0x03u

typedef struct
{
    bool     valid;
    uint16_t dst;
    uint8_t  clcwVc;
    uint16_t firstSeq;
    uint16_t total;
    int      csize;     /* message octets per chunk, fixed for the life of the message */
    uint16_t next;      /* next chunk index of the initial transmission */
    int      len;
    uint8_t  buf[SAT_BIGTM_MAX];
    uint8_t  retx[SAT_CHUNK_BITMAP]; /* chunks asked for again */
    uint16_t retxCount;
} Sat_ChunkOut_t;

/* Reassembly of a segmented telecommand, one per virtual channel. */
typedef struct
{
    uint8_t  buf[SAT_REASM_MAX];
    int      len;
    bool     active;
    uint8_t  map;
    uint32_t started;
} Sat_Reasm_t;

typedef struct Sat_Core
{
    uint16_t  scid;
    Sat_TxFn  tx;
    Sat_LogFn log;
    Sat_SbFn  sb;
    Sat_AuthRxFn authRx;
    void *    ctx;

    Sat_Farm_t   farm[SAT_TC_VC_COUNT];
    Sat_TxSlot_t q[SAT_TXQ_LEN];
    Sat_Reasm_t  reasm[SAT_TC_VC_COUNT];

    /* a telemetry packet larger than one frame, sent across frames by Sat_Tick */
    uint8_t  bigTm[SAT_BIGTM_MAX];
    int      bigLen;
    int      bigOff;
    uint8_t  bigVc;
    uint8_t  bigClcwVc;
    bool     bigActive;

    Sat_ChunkOut_t chunk[SAT_CHUNK_SLOTS];
    uint16_t naksRx, chunksRetx;

    /* SDLS state, one association pair per link: index SAT_TC_VC_GROUND is the
     * ground link (TC VC0 in, TM VC4 out), SAT_TC_VC_USER1 the user link (TC VC1
     * in, TM VC2 out).  A link's receive association starts when its key
     * arrives; its transmit association starts once every frame queued before
     * that moment has left, so nothing already queued changes key underneath. */
    struct
    {
        bool    rxActive;
        bool    txActive;
        bool    pendingTx;
        uint8_t sk[32];
    } sdls[SAT_TC_VC_COUNT];
    uint32_t sdlsTcOk, sdlsTcRejected, sdlsTmSent, sdlsStarts;
    int32_t  sdlsLastErr;

    /* Constellation phase (PROTOCOL.md).  The session key of the user this satellite
     * serves never leaves it: the feeder gets the derived ground link key and the next
     * serving satellite the derived next link key, each in an end to end transfer. */
    bool     sessValid;
    uint8_t  sessSk[32];  /* SK, or SK_n when the user was handed over to this satellite */
    uint8_t  sessOrd[32]; /* K_ord: authenticates hand over orders for this user */
    uint16_t feederScid;  /* satellite that holds the ground station link, from the time share */
    Sat_XferBuildFn xferBuild;
    Sat_XferOpenFn  xferOpen;
    void *          xferCtx;
    uint32_t xferSent, xferAccepted, xferRejected, ordersRejected;

    /* CLCW reporting: a TC VC with a pending report gets the OCF of the next
     * frame out, whatever that frame carries (CCSDS 232.1 allows any frame's
     * OCF to carry any VC's CLCW).  Transmission is paced by txPaceMs. */
    bool     clcwPending[SAT_TC_VC_COUNT];
    uint8_t  clcwLast;
    uint32_t txPaceMs;  /* air time scale in percent, see SAT_TX_PACE_PCT */
    uint32_t txHoldMs;  /* wait after the last frame before the next */
    uint32_t rxWindowMs;   /* receive window after a segment ack, see SAT_RX_WINDOW_MS */
    uint32_t rxQuietUntil; /* no housekeeping or bulk downlink before this time */
    uint32_t lastTx;
    bool     txEver;

    uint8_t  mcfc;
    uint8_t  vcfc[8];
    uint16_t hkSeq, ackSeq, relaySeq, idleSeq, authSeq;
    uint32_t hkPeriodMs, lastHk, now, lastRxBeat;
    bool     firstHk, timeSet;
    uint32_t timeBaseSec, timeBaseMs;

    /* Inter satellite link (constellation).  Frames are TM frames on VC3, fixed
     * 255 octets, packets spanned across frames by the first header pointer
     * (CCSDS 132.0), protected by SDLS from the pairwise ISL key.  Routing:
     * a packet for this satellite is handled here; one for the neighbour goes
     * over the ISL; the ground station is reached over the ISL when gsViaIsl
     * (the serving satellite of a user that the ground cannot hear). */
    Sat_IslTxFn   islTx;
    Sat_IslPeer_t isl[SAT_ISL_MAX];
    int           islN;        /* neighbours configured */
    int           gsPeer;      /* index of the neighbour toward the ground station, -1 when the ground is on own radio */
    uint16_t islFramesTx, islFramesRx, islRejected, islPacketsRx, islForwarded;
    uint32_t islLastTime;      /* last time share sent */

    /* counters reported in housekeeping */
    uint16_t rxFrames, crcErr, idErr, farmDiscard, cmdsOk, relayed, sbPackets;
    uint16_t segErr;    /* segments discarded: out of order, oversize or timed out */
    uint16_t reasmOk;   /* telecommands successfully reassembled                   */
    int8_t   lastRssi, lastSnr;
    uint8_t  clcwTurn;
} Sat_Core_t;

/* SDLS.  Sat_SdlsStart: a handshake completed on this satellite with session
 * key sk: key the user link, and the ground link too when the ground station
 * is on this satellite's radio, else hand sk to the neighbour over the ISL.
 * Sat_SdlsStartLink keys one link (receive now, transmit once the queue has
 * drained).  Sat_SdlsStop stops every association. */
void Sat_SdlsStart(Sat_Core_t *s, const uint8_t sk[32]);
void Sat_SdlsStartLink(Sat_Core_t *s, uint8_t link, const uint8_t sk[32]);
void Sat_SdlsStop(Sat_Core_t *s);

void Sat_CoreInit(Sat_Core_t *s, uint16_t scid, Sat_TxFn tx, Sat_LogFn log, Sat_SbFn sb, void *ctx);

/* A frame received by the uplink radio. */
void Sat_OnUplink(Sat_Core_t *s, const uint8_t *b, int n, int rssi, int snr, uint32_t now);
void Sat_OnRadioCrcError(Sat_Core_t *s);
void Sat_OnRxHeartbeat(Sat_Core_t *s, uint32_t now);

/* Call as often as possible: sends housekeeping and queued frames. */
void Sat_Tick(Sat_Core_t *s, uint32_t now);

/* Send a cFS telemetry packet down on the relay virtual channel.  A packet
 * that does not fit one frame is spanned across frames using the first header
 * pointer, as CCSDS 132.0 requires, and drained by Sat_Tick. */
void Sat_SendTlmPacket(Sat_Core_t *s, const uint8_t *packet, int len, uint32_t now);

/* True while a spanned telemetry packet is still being transmitted. */
bool Sat_TmBusy(const Sat_Core_t *s);

/* Inter satellite link.  Sat_SetIsl installs the transmit function; each
 * Sat_AddIslPeer adds a neighbour (its SCID, whether the ground station is
 * reached through it, the pairwise ISL key loaded at provisioning or NULL for
 * a clear link over which no session key is ever handed).  Returns the peer
 * index or -1. */
void Sat_SetIsl(Sat_Core_t *s, Sat_IslTxFn fn);
int  Sat_AddIslPeer(Sat_Core_t *s, uint16_t peerScid, bool towardGround, const uint8_t kisl[32]);
/* A frame received from a neighbour. */
void Sat_OnIsl(Sat_Core_t *s, const uint8_t *frame, int n, uint32_t now);
/* Send one space packet to neighbour `peer` (spanned across ISL frames), or
 * toward the ground station (Sat_IslSendPacket). */
void Sat_IslSendPacketTo(Sat_Core_t *s, int peer, const uint8_t *pkt, int plen);
void Sat_IslSendPacket(Sat_Core_t *s, const uint8_t *pkt, int plen);
/* Next hop toward destination identity dst (a terminal or a satellite SCID)
 * for a packet that arrived from neighbour `from` (-1: from own radio or
 * generated here); -1 when there is none. */
int  Sat_IslRoute(const Sat_Core_t *s, uint16_t dst, int from);

/* Install the authentication receive hook. */
void Sat_SetAuthRx(Sat_Core_t *s, Sat_AuthRxFn fn);
/* Send an authentication message down to terminal `dst`.  Spanned across
 * frames if it does not fit one. */
void Sat_SendAuth(Sat_Core_t *s, uint16_t dst, const uint8_t *msg, int len);
/* Spacecraft clock in seconds since 1970 (valid once SET_TIME has been received). */
uint32_t Sat_NowSec(const Sat_Core_t *s);

#ifdef __cplusplus
}
#endif
#endif /* SAT_CCSDS_H */
