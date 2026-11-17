/* sat_rf_app.c  -  SAT-1 radio link application for cFS.
 *
 * Replaces the UDP ground link (CI_LAB / TO_LAB) with the real satellite link:
 * CCSDS frames carried over the serial line to the laptop bridge and the LoRa
 * T-Beam radios.
 *
 *   ground station / user  <~LoRa~>  T-Beam  <-USB->  sat_bridge.py  <-serial->  SAT_RF (here)
 *
 * Line protocol on the serial link (same as the Stage 1 bridge):
 *   bridge -> satellite:  R,<rssi>,<snr>,<hex>   uplink frame received
 *                         E                      radio CRC error
 *                         H                      radio heartbeat
 *                         P                      ping
 *   satellite -> bridge:  TX,<hex>               downlink frame to transmit
 *                         LOG,<text>             log line
 *
 * the ICD commands (PING, SET_HK_RATE, SET_TIME), housekeeping and message relay
 * are handled by the link core (sat_ccsds.c).  A space packet with any other
 * APID is passed to the cFS software bus, so the ground can command every cFS
 * application over the radio.
 */
#define _DEFAULT_SOURCE
#define _GNU_SOURCE

#include "cfe.h"
#include "sat_ccsds.h"
#include "sat_auth.h"

#include <errno.h>
#include <stdlib.h>
#include <fcntl.h>
#include <string.h>
#include <termios.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/un.h>

#ifndef SAT_RF_DEVICE
#define SAT_RF_DEVICE "/dev/ttyAMA0"
#endif
#define SAT_RF_BAUD      B115200
#define SAT_RF_LINE_MAX  700
#define SAT_RF_SB_TIMEOUT 50 /* ms, keeps the loop responsive */

typedef struct
{
    Sat_Core_t   Core;
    int          Fd;
    CFE_SB_PipeId_t CmdPipe;
    char         Line[SAT_RF_LINE_MAX];
    int          LineLen;
    bool         LineOverflow;
    uint32       StartMs;
    uint32       RxLines;
    uint32       BadLines;
    uint32       TxFrames;
    uint32       SbSent;
    uint32       SbErrors;
} SAT_RF_Global_t;

static SAT_RF_Global_t SAT_RF_Global;

static const char SAT_RF_HEX[] = "0123456789ABCDEF";

/* ---------------- milliseconds since app start ---------------- */
static uint32 SAT_RF_NowMs(void)
{
    struct timespec ts;
    uint64_t        ms;

    clock_gettime(CLOCK_MONOTONIC, &ts);
    ms = (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
    if (SAT_RF_Global.StartMs == 0)
    {
        SAT_RF_Global.StartMs = (uint32)(ms & 0xFFFFFFFFu);
    }
    return (uint32)((ms & 0xFFFFFFFFu) - SAT_RF_Global.StartMs);
}

/* ---------------- serial port ---------------- */
static int SAT_RF_OpenPort(const char *dev)
{
    struct termios tio;
    int            fd;

    fd = open(dev, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0)
    {
        return -1;
    }
    if (tcgetattr(fd, &tio) == 0)
    {
        /* raw mode, written out so no non-standard helpers are needed */
        tio.c_iflag &= (tcflag_t) ~(IGNBRK | BRKINT | PARMRK | ISTRIP | INLCR | IGNCR | ICRNL | IXON);
        tio.c_oflag &= (tcflag_t) ~OPOST;
        tio.c_lflag &= (tcflag_t) ~(ECHO | ECHONL | ICANON | ISIG | IEXTEN);
        tio.c_cflag &= (tcflag_t) ~(CSIZE | PARENB);
        tio.c_cflag |= (tcflag_t)(CS8 | CLOCAL | CREAD);
        cfsetispeed(&tio, SAT_RF_BAUD);
        cfsetospeed(&tio, SAT_RF_BAUD);
        tio.c_cc[VMIN]  = 0;
        tio.c_cc[VTIME] = 0;
        tcsetattr(fd, TCSANOW, &tio);
        tcflush(fd, TCIFLUSH);
    }
    return fd;
}

static void SAT_RF_WriteAll(const char *s, int n)
{
    int off = 0;
    int r;

    while (off < n)
    {
        r = (int)write(SAT_RF_Global.Fd, s + off, (size_t)(n - off));
        if (r > 0)
        {
            off += r;
        }
        else if (r < 0 && (errno == EAGAIN || errno == EINTR))
        {
            usleep(1000);
        }
        else
        {
            return; /* give up rather than block the flight software */
        }
    }
}

/* ---------------- callbacks used by the link core ---------------- */
static void SAT_RF_TxFrame(const uint8_t *frame, int n, void *ctx)
{
    char b[4 + 2 * SAT_MAX_FRAME + 2];
    int  k = 0;
    int  i;

    (void)ctx;
    b[k++] = 'T';
    b[k++] = 'X';
    b[k++] = ',';
    for (i = 0; i < n; i++)
    {
        b[k++] = SAT_RF_HEX[frame[i] >> 4];
        b[k++] = SAT_RF_HEX[frame[i] & 0x0F];
    }
    b[k++] = '\n';
    SAT_RF_WriteAll(b, k);
    SAT_RF_Global.TxFrames++;
}

static void SAT_RF_LogLine(const char *msg, void *ctx)
{
    char b[256];
    int  n;

    (void)ctx;
    /* authentication lines also go to the cFS event log (sat1.log on the board),
       so provisioning and the A72 timings are kept even when the radio log is not */
    if (strncmp(msg, "auth:", 5) == 0 || strncmp(msg, "SDLS", 4) == 0)
    {
        CFE_EVS_SendEvent(20, CFE_EVS_EventType_INFORMATION, "%.120s", msg);
    }
    n = snprintf(b, sizeof b, "LOG,%s\n", msg);
    if (n > (int)sizeof b - 1)
    {
        n = (int)sizeof b - 1;
    }
    SAT_RF_WriteAll(b, n);
}

/* ---------------- inter satellite link ----------------
 * On the Versal the satellites are cFS instances; each ISL is a Unix datagram
 * socket pair, one 255 octet TM frame per datagram, one socket per neighbour:
 *   SAT_ISL_PEERS      "0x101:/root/cpu2/auth/isl_sat1_sat2.key,0x103:/root/cpu2/auth/isl_sat2_sat3.key"
 *                      (an empty key path gives a clear link)
 *   SAT_GS_PEER        the neighbour's SCID through which the ground station is reached (unset: own radio)
 *   sockets            /tmp/isl_<lower scid>_<higher scid>_<own scid>.sock, the peer's is the same with its SCID
 * The older single neighbour form SAT_ISL_PEER, SAT_ISL_KEY, SAT_GS_VIA_ISL still works.
 * A real ISL transceiver would replace the socket; the frames are the same. */
static int                SAT_RF_IslFd[SAT_ISL_MAX] = {-1, -1};
static struct sockaddr_un SAT_RF_IslPeer[SAT_ISL_MAX];
static uint16_t           SAT_RF_Scid = SAT_SCID_SAT1;
/* RF inter satellite link (SAT_ISL_RF=1): ISL frames leave on the satellite's serial line as
 *   ITX,<peer SCID, 3 hex digits>,<frame hex>
 * and the bridge puts them on this satellite's ISL transmit radio.  A frame heard by the ISL
 * receive radio comes back as   I,<rssi>,<snr>,<frame hex>.   Transmit and receive use two
 * radios on two frequencies, so the link is full duplex.  The frames are the ones the socket
 * carried: nothing in the core changes. */
static bool     SAT_RF_IslRf = false;
static uint16_t SAT_RF_IslScid[SAT_ISL_MAX];
static uint32   SAT_RF_IslRfTx = 0, SAT_RF_IslRfRx = 0;

static void SAT_RF_IslTx(const uint8_t *frame, int n, int peer, void *ctx)
{
    (void)ctx;
    if (SAT_RF_IslRf && peer >= 0 && peer < SAT_ISL_MAX && n > 0 && n <= SAT_MAX_FRAME)
    {
        char b[8 + 2 * SAT_MAX_FRAME + 2];
        int  k = snprintf(b, 9, "ITX,%03X,", (unsigned)(SAT_RF_IslScid[peer] & 0xFFFu));
        int  i;

        for (i = 0; i < n; i++)
        {
            b[k++] = SAT_RF_HEX[frame[i] >> 4];
            b[k++] = SAT_RF_HEX[frame[i] & 0x0F];
        }
        b[k++] = '\n';
        SAT_RF_WriteAll(b, k);
        SAT_RF_IslRfTx++;
        return;
    }
    if (peer >= 0 && peer < SAT_ISL_MAX && SAT_RF_IslFd[peer] >= 0)
    {
        (void)sendto(SAT_RF_IslFd[peer], frame, (size_t)n, 0, (struct sockaddr *)&SAT_RF_IslPeer[peer],
                     sizeof SAT_RF_IslPeer[peer]);
    }
}

static void SAT_RF_IslAdd(uint16_t peerScid, const char *keyPath, bool towardGround)
{
    char               own[108], other[108], b[160];
    struct sockaddr_un a;
    uint8_t            key[32];
    bool               have = false;
    uint16_t           lo = SAT_RF_Scid < peerScid ? SAT_RF_Scid : peerScid;
    uint16_t           hi = SAT_RF_Scid < peerScid ? peerScid : SAT_RF_Scid;
    int                idx, fd;

    if (SAT_RF_IslRf)
    {
        if (keyPath != NULL && keyPath[0] != 0)
        {
            FILE *f = fopen(keyPath, "rb");
            if (f != NULL)
            {
                have = fread(key, 1, 32, f) == 32;
                fclose(f);
            }
            if (!have)
            {
                SAT_RF_LogLine("ISL: key file unreadable, link in clear", NULL);
            }
        }
        idx = Sat_AddIslPeer(&SAT_RF_Global.Core, peerScid, towardGround, have ? key : NULL);
        memset(key, 0, sizeof key);
        if (idx >= 0)
        {
            SAT_RF_IslScid[idx] = peerScid;
            snprintf(b, sizeof b, "ISL: RF link to SAT %04X, full duplex, on the ISL radios", (unsigned)peerScid);
            SAT_RF_LogLine(b, NULL);
        }
        return;
    }

    snprintf(own, sizeof own, "/tmp/isl_%03x_%03x_%03x.sock", (unsigned)lo, (unsigned)hi, (unsigned)SAT_RF_Scid);
    snprintf(other, sizeof other, "/tmp/isl_%03x_%03x_%03x.sock", (unsigned)lo, (unsigned)hi, (unsigned)peerScid);
    fd = socket(AF_UNIX, SOCK_DGRAM, 0);
    if (fd < 0)
    {
        SAT_RF_LogLine("ISL: socket failed", NULL);
        return;
    }
    memset(&a, 0, sizeof a);
    a.sun_family = AF_UNIX;
    snprintf(a.sun_path, sizeof a.sun_path, "%s", own);
    unlink(own);
    if (bind(fd, (struct sockaddr *)&a, sizeof a) < 0)
    {
        snprintf(b, sizeof b, "ISL: bind %s failed (errno %d)", own, errno);
        SAT_RF_LogLine(b, NULL);
        close(fd);
        return;
    }
    fcntl(fd, F_SETFL, O_NONBLOCK);
    if (keyPath != NULL && keyPath[0] != 0)
    {
        FILE *f = fopen(keyPath, "rb");
        if (f != NULL)
        {
            have = fread(key, 1, 32, f) == 32;
            fclose(f);
        }
        if (!have)
        {
            SAT_RF_LogLine("ISL: key file unreadable, link in clear", NULL);
        }
    }
    idx = Sat_AddIslPeer(&SAT_RF_Global.Core, peerScid, towardGround, have ? key : NULL);
    memset(key, 0, sizeof key);
    if (idx < 0)
    {
        close(fd);
        return;
    }
    SAT_RF_IslFd[idx] = fd;
    memset(&SAT_RF_IslPeer[idx], 0, sizeof SAT_RF_IslPeer[idx]);
    SAT_RF_IslPeer[idx].sun_family = AF_UNIX;
    snprintf(SAT_RF_IslPeer[idx].sun_path, sizeof SAT_RF_IslPeer[idx].sun_path, "%s", other);
    snprintf(b, sizeof b, "ISL: socket %s to %s", own, other);
    SAT_RF_LogLine(b, NULL);
}

static void SAT_RF_IslInit(void)
{
    char     spec[512] = "";
    char    *tok, *save = NULL;
    uint16_t gsPeer = getenv("SAT_GS_PEER") != NULL ? (uint16_t)strtoul(getenv("SAT_GS_PEER"), NULL, 0) : 0;

    SAT_RF_IslRf = getenv("SAT_ISL_RF") != NULL && atoi(getenv("SAT_ISL_RF")) != 0;

    if (getenv("SAT_ISL_PEERS") != NULL)
    {
        snprintf(spec, sizeof spec, "%s", getenv("SAT_ISL_PEERS"));
    }
    else if (getenv("SAT_ISL_PEER") != NULL)
    {
        snprintf(spec, sizeof spec, "%s:%s", getenv("SAT_ISL_PEER"),
                 getenv("SAT_ISL_KEY") != NULL ? getenv("SAT_ISL_KEY") : "");
        if (getenv("SAT_GS_VIA_ISL") != NULL)
        {
            gsPeer = (uint16_t)strtoul(getenv("SAT_ISL_PEER"), NULL, 0);
        }
    }
    if (spec[0] == 0)
    {
        return;
    }
    Sat_SetIsl(&SAT_RF_Global.Core, SAT_RF_IslTx);
    for (tok = strtok_r(spec, ",", &save); tok != NULL; tok = strtok_r(NULL, ",", &save))
    {
        char    *colon = strchr(tok, ':');
        uint16_t peer  = (uint16_t)strtoul(tok, NULL, 0);
        SAT_RF_IslAdd(peer, colon != NULL ? colon + 1 : NULL, peer == gsPeer);
    }
}

static void SAT_RF_PumpIsl(void)
{
    uint8_t f[SAT_MAX_FRAME + 1];
    ssize_t n;
    int     i;

    for (i = 0; i < SAT_ISL_MAX; i++)
    {
        while (SAT_RF_IslFd[i] >= 0 && (n = recv(SAT_RF_IslFd[i], f, sizeof f, 0)) > 0)
        {
            Sat_OnIsl(&SAT_RF_Global.Core, f, (int)n, SAT_RF_NowMs());
        }
    }
}

/* ---------------- three party authentication glue ---------------- */
static Auth_Sat_t SAT_RF_Auth;
static Auth_Peers_t   SAT_RF_Peers;                                  /* certificates of the other satellites */
static Auth_XferCtx_t SAT_RF_Xfer = {&SAT_RF_Auth, &SAT_RF_Peers};

static void SAT_RF_AuthSend(uint16_t dst, const uint8_t *msg, int len, void *ctx)
{
    (void)ctx;
    Sat_SendAuth(&SAT_RF_Global.Core, dst, msg, len);
}

static void SAT_RF_AuthRx(uint16_t src, const uint8_t *msg, int len, uint32_t nowSec, void *ctx)
{
    (void)ctx;
    Auth_OnMessage(&SAT_RF_Auth, src, msg, len, nowSec);
}

/* A handshake has completed: key the SDLS associations (NASA CryptoLib) from
   the confirmed session key, unless SAT_NO_SDLS is set in the unit. */
static void SAT_RF_AuthSession(const uint8_t sk[32], void *ctx)
{
    (void)ctx;
    if (getenv("SAT_NO_SDLS") == NULL)
    {
        Sat_SdlsStart(&SAT_RF_Global.Core, sk);
    }
}

/* Load the provisioning bundle from SAT_AUTH_DIR (default /root/cpu1/auth). */
static void SAT_RF_AuthInit(void)
{
    const char *dir = getenv("SAT_AUTH_DIR");
    char        path[256], b[160];
    int         r;

    if (dir == NULL || dir[0] == 0)
    {
        dir = "/root/cpu1/auth";
    }
    Auth_Init(&SAT_RF_Auth, SAT_RF_AuthSend, SAT_RF_LogLine, NULL);
    Auth_SetSessionHook(&SAT_RF_Auth, SAT_RF_AuthSession);
    snprintf(path, sizeof path, "%s/%s.bundle", dir,
             getenv("SAT_BUNDLE") != NULL ? getenv("SAT_BUNDLE") : (SAT_RF_Scid == 0x102 ? "sat2" : "sat1"));
    r = Auth_LoadBundle(&SAT_RF_Auth, path);
    if (r == 0)
    {
        snprintf(path, sizeof path, "%s/gs.cert", dir);
        r = Auth_LoadPeerCert(&SAT_RF_Auth, path);
    }
    if (r == 0)
    {
        snprintf(path, sizeof path, "%s/ue1.cert", dir);
        (void)Auth_LoadUserCert(&SAT_RF_Auth, path); /* optional pre provisioning */
        (void)Auth_LoadSatCerts(&SAT_RF_Auth, &SAT_RF_Peers, dir); /* for end to end key transfer */
        SAT_RF_Global.Core.xferBuild = Auth_XferBuildHook;
        SAT_RF_Global.Core.xferOpen  = Auth_XferOpenHook;
        SAT_RF_Global.Core.xferCtx   = &SAT_RF_Xfer;
        snprintf(SAT_RF_Auth.crl_path, sizeof SAT_RF_Auth.crl_path, "%s/crl.bin", dir);
        (void)Auth_LoadCrl(&SAT_RF_Auth, SAT_RF_Auth.crl_path); /* revocation list, when one is provisioned */
        if (getenv("SAT_AUTH_FRESH_S") != NULL)
            Auth_SetFresh(&SAT_RF_Auth, (uint32_t)atoi(getenv("SAT_AUTH_FRESH_S")));
        if (getenv("SAT_AUTH_REF") != NULL)
        {
            SAT_RF_Auth.full_certs = false;
        }
        Sat_SetAuthRx(&SAT_RF_Global.Core, SAT_RF_AuthRx);
        snprintf(b, sizeof b, "auth: provisioned as %04X for ground %04X, certificates %s", SAT_RF_Auth.ident,
                 SAT_RF_Auth.id_gs, SAT_RF_Auth.full_certs ? "full" : "by reference");
    }
    else
    {
        snprintf(b, sizeof b, "auth: NOT provisioned (%d), handshakes disabled, dir %s", r, dir);
    }
    SAT_RF_LogLine(b, NULL);
}

/* A space packet that is not part of the ICD: publish it on the software bus so
 * the cFS applications receive it as a command. */
static bool SAT_RF_ToSoftwareBus(const uint8_t *packet, int len, uint8_t tcVc, void *ctx)
{
    CFE_SB_Buffer_t *BufPtr;
    CFE_Status_t     Status;

    (void)tcVc;
    (void)ctx;

    if (len < 7 || len > CFE_MISSION_SB_MAX_SB_MSG_SIZE)
    {
        return false;
    }
    BufPtr = CFE_SB_AllocateMessageBuffer((size_t)len);
    if (BufPtr == NULL)
    {
        SAT_RF_Global.SbErrors++;
        return false;
    }
    memcpy(BufPtr, packet, (size_t)len);
    Status = CFE_SB_TransmitBuffer(BufPtr, false);
    if (Status != CFE_SUCCESS)
    {
        SAT_RF_Global.SbErrors++;
        CFE_SB_ReleaseMessageBuffer(BufPtr);
        return false;
    }
    SAT_RF_Global.SbSent++;
    return true;
}

/* ---------------- input line handling ---------------- */
static int SAT_RF_HexVal(char c)
{
    if (c >= '0' && c <= '9')
    {
        return c - '0';
    }
    if (c >= 'A' && c <= 'F')
    {
        return c - 'A' + 10;
    }
    if (c >= 'a' && c <= 'f')
    {
        return c - 'a' + 10;
    }
    return -1;
}

static bool SAT_RF_ParseInt(const char **p, int *v)
{
    const char *s   = *p;
    bool        neg = false;
    long        x   = 0;

    if (*s == '-')
    {
        neg = true;
        s++;
    }
    if (*s < '0' || *s > '9')
    {
        return false;
    }
    while (*s >= '0' && *s <= '9')
    {
        x = x * 10 + (*s - '0');
        s++;
    }
    if (*s == '.')
    {
        s++;
        while (*s >= '0' && *s <= '9')
        {
            s++;
        }
    }
    *v = (int)(neg ? -x : x);
    *p = s;
    return true;
}

static void SAT_RF_HandleLine(const char *s)
{
    uint32      now = SAT_RF_NowMs();
    const char *p;
    int         rssi;
    int         snr;
    int         hl;
    int         i;
    uint8_t     f[SAT_MAX_FRAME];
    char        b[160];

    SAT_RF_Global.RxLines++;

    if (s[0] == 'H' && s[1] == 0)
    {
        Sat_OnRxHeartbeat(&SAT_RF_Global.Core, now);
        return;
    }
    if (s[0] == 'E' && s[1] == 0)
    {
        Sat_OnRadioCrcError(&SAT_RF_Global.Core);
        return;
    }
    if (s[0] == 'P' && s[1] == 0)
    {
        snprintf(b, sizeof b, "PONG SAT-%u SCID 0x%03X up %u s lines %u tx %u sb %u bad %u", (unsigned)(SAT_RF_Scid & 0xF), (unsigned)SAT_RF_Scid,
                 (unsigned)(now / 1000u), (unsigned)SAT_RF_Global.RxLines, (unsigned)SAT_RF_Global.TxFrames,
                 (unsigned)SAT_RF_Global.SbSent, (unsigned)SAT_RF_Global.BadLines);
        SAT_RF_LogLine(b, NULL);
        return;
    }
    if ((s[0] != 'R' && s[0] != 'I') || s[1] != ',')
    {
        SAT_RF_Global.BadLines++;
        return;
    }

    p = s + 2;
    if (!SAT_RF_ParseInt(&p, &rssi) || *p++ != ',')
    {
        SAT_RF_Global.BadLines++;
        return;
    }
    if (!SAT_RF_ParseInt(&p, &snr) || *p++ != ',')
    {
        SAT_RF_Global.BadLines++;
        return;
    }
    hl = (int)strlen(p);
    if (hl < 2 || (hl & 1) || (hl / 2) > SAT_MAX_FRAME)
    {
        SAT_RF_Global.BadLines++;
        return;
    }
    for (i = 0; i < hl / 2; i++)
    {
        int h = SAT_RF_HexVal(p[2 * i]);
        int l = SAT_RF_HexVal(p[2 * i + 1]);

        if (h < 0 || l < 0)
        {
            SAT_RF_Global.BadLines++;
            return;
        }
        f[i] = (uint8_t)((h << 4) | l);
    }
    if (s[0] == 'I')
    {
        /* a frame from the ISL receive radio: the same entry point the socket fed */
        if (SAT_RF_IslRf)
        {
            SAT_RF_IslRfRx++;
            Sat_OnIsl(&SAT_RF_Global.Core, f, hl / 2, now);
        }
        return;
    }
    Sat_OnUplink(&SAT_RF_Global.Core, f, hl / 2, rssi, snr, now);
}

static void SAT_RF_PumpRx(void)
{
    uint8_t buf[512];
    int     n;
    int     i;

    for (;;)
    {
        n = (int)read(SAT_RF_Global.Fd, buf, sizeof buf);
        if (n <= 0)
        {
            return;
        }
        for (i = 0; i < n; i++)
        {
            char c = (char)buf[i];

            if (c == '\n' || c == '\r')
            {
                if (SAT_RF_Global.LineLen && !SAT_RF_Global.LineOverflow)
                {
                    SAT_RF_Global.Line[SAT_RF_Global.LineLen] = 0;
                    SAT_RF_HandleLine(SAT_RF_Global.Line);
                }
                SAT_RF_Global.LineLen      = 0;
                SAT_RF_Global.LineOverflow = false;
            }
            else if (SAT_RF_Global.LineLen < SAT_RF_LINE_MAX - 1)
            {
                SAT_RF_Global.Line[SAT_RF_Global.LineLen++] = c;
            }
            else
            {
                SAT_RF_Global.LineOverflow = true;
            }
        }
    }
}

/* ---------------- application ---------------- */
static void SAT_RF_TaskInit(void)
{
    const char *dev = getenv("SAT_RF_DEVICE");
    char        b[160];

    memset(&SAT_RF_Global, 0, sizeof(SAT_RF_Global));
    SAT_RF_Global.Fd = -1;

    CFE_EVS_Register(NULL, 0, CFE_EVS_EventFilter_BINARY);

    if (dev == NULL || dev[0] == 0)
    {
        dev = SAT_RF_DEVICE;
    }
    SAT_RF_Global.Fd = SAT_RF_OpenPort(dev);
    if (SAT_RF_Global.Fd < 0)
    {
        CFE_EVS_SendEvent(10, CFE_EVS_EventType_ERROR, "SAT_RF: cannot open radio link %s (errno %d)", dev, errno);
    }
    else
    {
        CFE_ES_WriteToSysLog("SAT_RF: radio link on %s at 115200\n", dev);
    }

    /* SAT_SCID selects which satellite this instance is (cpu1: SAT-1 0x101, cpu2: SAT-2 0x102) */
    if (getenv("SAT_SCID") != NULL)
    {
        SAT_RF_Scid = (uint16_t)strtoul(getenv("SAT_SCID"), NULL, 0);
    }
    Sat_CoreInit(&SAT_RF_Global.Core, SAT_RF_Scid, SAT_RF_TxFrame, SAT_RF_LogLine, SAT_RF_ToSoftwareBus, NULL);
    if (getenv("SAT_LORA_SF") != NULL)
    {
        Sat_SetLoraSf((unsigned)atoi(getenv("SAT_LORA_SF")));
    }
    if (getenv("SAT_RX_WINDOW_MS") != NULL)
    {
        SAT_RF_Global.Core.rxWindowMs = (uint32_t)atoi(getenv("SAT_RX_WINDOW_MS"));
    }
    if (getenv("SAT_TX_PACE_PCT") != NULL)
    {
        SAT_RF_Global.Core.txPaceMs = (uint32_t)atoi(getenv("SAT_TX_PACE_PCT"));
    }
    SAT_RF_AuthInit();
    SAT_RF_IslInit();

    CFE_SB_CreatePipe(&SAT_RF_Global.CmdPipe, 16, "SAT_RF_PIPE");

    snprintf(b, sizeof b, "SAT-%u radio link ready, SCID 0x%03X, HK every 10 s", (unsigned)(SAT_RF_Scid & 0xF),
             (unsigned)SAT_RF_Scid);
    SAT_RF_LogLine(b, NULL);
    CFE_EVS_SendEvent(1, CFE_EVS_EventType_INFORMATION, "SAT_RF Initialized. SCID 0x%03X on %s",
                      (unsigned)SAT_RF_Scid, dev);
}

void SAT_RF_AppMain(void)
{
    uint32           RunStatus = CFE_ES_RunStatus_APP_RUN;
    CFE_SB_Buffer_t *SBBufPtr;

    SAT_RF_TaskInit();

    while (CFE_ES_RunLoop(&RunStatus) == true)
    {
        /* Wait a short time on the software bus, which also paces the loop. */
        if (CFE_SB_ReceiveBuffer(&SBBufPtr, SAT_RF_Global.CmdPipe, SAT_RF_SB_TIMEOUT) == CFE_SUCCESS)
        {
            /* nothing subscribed yet; telemetry forwarding is added next */
        }

        if (SAT_RF_Global.Fd >= 0)
        {
            SAT_RF_PumpRx();
        }
        SAT_RF_PumpIsl();
        Sat_Tick(&SAT_RF_Global.Core, SAT_RF_NowMs());
        Auth_Tick(&SAT_RF_Auth, Sat_NowSec(&SAT_RF_Global.Core));
    }

    if (SAT_RF_Global.Fd >= 0)
    {
        close(SAT_RF_Global.Fd);
    }
    CFE_ES_ExitApp(RunStatus);
}
