/*
 * SAT-1 SDLS: CCSDS 355.0 security on the user link, performed by NASA
 * CryptoLib (github.com/nasa/CryptoLib, commit dbcb115, unmodified), keyed
 * from the session key of the post quantum three party handshake.
 *
 * This wrapper only configures CryptoLib for the testbed and calls its public
 * API.  All SDLS processing (security header and trailer, security
 * association lookup, IV and anti replay checks, authenticated data, FECF) is
 * CryptoLib's.  The cipher is AES-256-GCM from libpqsat through CryptoLib's
 * CRYPTO_CUSTOM backend option.
 *
 * Security associations
 *   SPI 1  TC VC1  user -> satellite      AES-256-GCM, 12 octet IV, 16 octet MAC
 *   SPI 2  TM VC2  satellite -> terminals AES-256-GCM, 12 octet IV, 16 octet MAC
 * CryptoLib selects an SA by (TFVN, SCID, VCID); TC and TM version 1 frames
 * share TFVN 0, so the protected downlink uses a VCID distinct from the
 * protected uplink.  TM VC1 remains the clear relay channel.
 * Keys and initial IVs from SK:
 *   K_tc  = KDF(SK, "SDLS TC VC1 key")   salt_tc = KDF(SK, "SDLS TC VC1 iv")[0:4]
 *   K_tm  = KDF(SK, "SDLS TM VC2 key")   salt_tm = KDF(SK, "SDLS TM VC2 iv")[0:4]
 * IV = salt || 8 octet counter.  The sending end starts its counter at 1 and
 * the receiving end at 0: CryptoLib sends with the current IV and then
 * increments it, and accepts a received IV only above the last one accepted.
 * The IV is transmitted and incremented per frame by CryptoLib; anti replay
 * uses the IV with a window of SDLS_ARSN_WINDOW.
 *
 * TM frames on a protected channel are fixed length (SDLS_TM_FRAME_LEN), as
 * CCSDS 132.0 requires and CryptoLib enforces.
 */
#ifndef SAT_SDLS_H
#define SAT_SDLS_H

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define SDLS_SPI_TC 1u      /* TC VC1, user to satellite */
#define SDLS_SPI_TM 2u      /* TM VC2, satellite to both terminals */
#define SDLS_SPI_TC_GS 6u   /* TC VC0, ground station to satellite (an SPI whose CryptoLib default passes its own validation) */
#define SDLS_SPI_TM_GS 9u   /* TM VC4, satellite to the ground station */
#define SDLS_VC_TM_GROUND 4u /* protected TM downlink to the ground station */
#define SDLS_LINK_GROUND 0  /* satellite side: the ground station link (TC VC0 in, TM VC4 out) */
#define SDLS_LINK_USER 1    /* satellite side: the user link (TC VC1 in, TM VC2 out) */
#define SDLS_VC_USER 1u     /* protected TC uplink from the user */
#define SDLS_VC_GROUND 0u   /* protected TC uplink from the ground station */
#define SDLS_VC_TM_USER 2u  /* protected TM downlink to the terminals */
/* An SPI names the receiver's association, so each ISL direction has its own.
 * For the link between the lower SCID L and the higher SCID H the direction
 * L to H uses SPI 16 + 2 (H & 0xF) and H to L the next one, so a satellite in a
 * chain holds distinct associations for each neighbour (SPIs 16 to 47 are
 * unpopulated in CryptoLib's in memory table and pass its validation as they are). */
#define SDLS_SPI_ISL_BASE 16u
#define SDLS_ISL_MAX 2        /* neighbours per satellite (a chain) */
#define SDLS_VC_ISL 3u      /* inter satellite link toward the neighbour with the lower SCID */
#define SDLS_VC_ISL_UP 5u   /* inter satellite link toward the neighbour with the higher SCID; CryptoLib selects a
                               transmit association by (SCID, VCID), so a satellite with two neighbours needs two VCs */
#define SDLS_ROLE_SATELLITE 0 /* receives TC VC0 and VC1, sends TM VC2 */
#define SDLS_ROLE_USER 1      /* sends TC VC1, receives TM VC2 */
#define SDLS_ROLE_GROUND 2    /* sends TC VC0, receives TM VC2 */
#define SDLS_HDR_LEN 14      /* SPI 2 + IV 12 */
#define SDLS_MAC_LEN 16
#define SDLS_OVERHEAD 30
#define SDLS_TM_FRAME_LEN 255 /* fixed TM frame length on the protected channel */
#define SDLS_ARSN_WINDOW 2000 /* frames a receiver may miss (deaf while transmitting, loss) */

/* Configure CryptoLib for spacecraft scid.  Both SAs start stopped. */
int32_t SatSdls_Init(uint16_t scid);

/* Key the role's SAs from the session key and make them operational.  Replaces
 * any running association (rekey): counters restart from the new initial IVs.
 * The satellite may start its receive side first and its transmit side once
 * frames queued under the old association have left (SatSdls_StartTx).
 * SatSdls_Start* with SDLS_ROLE_SATELLITE key both links; a satellite keys
 * one link at a time with SatSdls_LinkRx / SatSdls_LinkTx (SDLS_LINK_*). */
int32_t SatSdls_LinkRx(const uint8_t sk[32], int link);
int32_t SatSdls_LinkTx(const uint8_t sk[32], int link);
void    SatSdls_LinkStop(int link);
int32_t SatSdls_Start(const uint8_t sk[32], int role);
int32_t SatSdls_StartRx(const uint8_t sk[32], int role);
int32_t SatSdls_StartTx(const uint8_t sk[32], int role);

/* Inter satellite link.  Two associations keyed from the pairwise ISL key
 * loaded at provisioning (CCSDS 355.0 pre shared key, one per link):
 *   transmit  TM VC3 under this satellite's SCID,  K = KDF(K_ISL, "SDLS ISL <own>><peer> key")
 *   receive   TM VC3 under the neighbour's SCID,   K = KDF(K_ISL, "SDLS ISL <peer>><own> key")
 * so each direction has its own key and IV salt and CryptoLib selects the
 * receive association by the SCID in the neighbour's frame header. */
int32_t SatSdls_IslStart(const uint8_t kisl[32], uint16_t peerScid);   /* one call per neighbour */
void    SatSdls_IslStop(void);
int     SatSdls_IslActive(void);
/* The TM virtual channel this satellite uses toward peerScid. */
uint8_t SatSdls_IslVc(uint16_t ownScid, uint16_t peerScid);
/* Protect one ISL frame to peerScid in place (layout as SatSdls_TmApply); the frame
 * header must carry SatSdls_IslVc(own, peer). */
int32_t SatSdls_IslApply(uint8_t *frame, uint16_t peerScid);

/* Stop both SAs (CCSDS 355.1 Stop SA).  Frames on VC1 then pass in clear. */
void SatSdls_Stop(void);

int SatSdls_Active(void);

/* User terminal: protect a clear TC frame (header, segment header, data,
 * FECF).  out receives the protected frame; returns 0 or a CryptoLib error. */
int32_t SatSdls_TcApply(const uint8_t *in, int inlen, uint8_t *out, int outmax, int *outlen);

/* Satellite: verify and decrypt a protected TC frame.  pdu receives the clear
 * frame data field after the segment header; seg the segment header.
 * Returns 0, or a CryptoLib error (MAC failure, replay, unknown SPI, ...). */
int32_t SatSdls_TcProcess(const uint8_t *in, int inlen, uint8_t *seg, uint8_t *pdu, int pdumax, int *pdulen);

/* Satellite: frame is a SDLS_TM_FRAME_LEN octet TM frame laid out as
 * header 6 | security header 14 (filled here) | data | MAC 16 | OCF 4 | FECF 2.
 * Encrypts the data in place and fills SPI (from the frame's VCID: VC2 user,
 * VC4 ground), IV, MAC and FECF. */
int32_t SatSdls_TmApply(uint8_t *frame);

/* Ground and user: verify and decrypt a protected TM frame.  data receives the
 * clear frame data field.  Returns 0 or a CryptoLib error. */
int32_t SatSdls_TmProcess(const uint8_t *in, int inlen, uint8_t *data, int datamax, int *datalen);

/* Counters for the evidence: frames accepted, and rejections by cause. */
typedef struct
{
    uint32_t tc_ok, tc_bad_mac, tc_replay, tc_other;
    uint32_t tm_ok, tm_bad_mac, tm_replay, tm_other;
    int32_t  last_error;
} SatSdls_Stats_t;
void SatSdls_GetStats(SatSdls_Stats_t *st);

#ifdef __cplusplus
}
#endif
#endif
