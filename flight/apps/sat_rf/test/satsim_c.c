/* Host simulator for the C satellite core (same protocol as satsim.cpp). */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include "sat_ccsds.h"
#include "sat_auth.h"

static uint32_t g_now = 0;

static void tx(const uint8_t *b, int n, void *ctx)
{
    int i;
    (void)ctx;
    printf("TX,%u,", (unsigned)g_now);
    for (i = 0; i < n; i++) printf("%02X", b[i]);
    printf("\n");
    fflush(stdout);
}
static void lg(const char *m, void *ctx) { (void)ctx; printf("LOG,%s\n", m); fflush(stdout); }
/* inter satellite link frame out: the harness pipes it to the neighbour process */
static void isl_tx(const uint8_t *b, int n, int peer, void *ctx)
{
    int i;
    (void)ctx;
    printf("ISL%d,%u,", peer, (unsigned)g_now);
    for (i = 0; i < n; i++) printf("%02X", b[i]);
    printf("\n");
    fflush(stdout);
}
static int unhex(const char *p, uint8_t *buf, int max)
{
    size_t hl = strlen(p), i;
    size_t n = hl / 2;
    if ((int)n > max) n = (size_t)max;
    for (i = 0; i < n; i++)
    {
        char t[3] = {p[2*i], p[2*i+1], 0};
        buf[i] = (uint8_t)strtoul(t, NULL, 16);
    }
    return (int)n;
}

static Sat_Core_t  sat;
static Auth_Sat_t  auth;
static Auth_Peers_t   peers;                      /* certificates of the other satellites */
static Auth_XferCtx_t xctx = {&auth, &peers};
static void auth_send(uint16_t dst, const uint8_t *m, int n, void *ctx) { (void)ctx; Sat_SendAuth(&sat, dst, m, n); }
static int g_external = 0; /* SAT_AUTH_EXTERNAL=1: the harness runs the satellite role of the protocol */
static void auth_rx(uint16_t src, const uint8_t *m, int n, uint32_t now, void *ctx)
{
    (void)ctx;
    if (g_external)
    {
        int i;
        printf("AUTH,%04X,", (unsigned)src);
        for (i = 0; i < n; i++) printf("%02X", m[i]);
        printf("\n");
        fflush(stdout);
        return;
    }
    Auth_OnMessage(&auth, src, m, n, now);
}
static void on_session(const uint8_t sk[32], void *ctx) { (void)ctx; if (!getenv("SAT_NO_SDLS")) Sat_SdlsStart(&sat, sk); }

int main(void)
{
    static char line[4096];
    const char *dir = getenv("SAT_AUTH_DIR");

    /* SAT_SCID selects the satellite (default SAT-1, 0x101); SAT_BUNDLE its bundle name.
     * SAT_ISL_PEER=<scid> enables the inter satellite link to that neighbour,
     * SAT_GS_VIA_ISL=1 says the ground station is behind it, SAT_ISL_KEY=<path> the
     * pairwise ISL key file (32 bytes) loaded at provisioning. */
    uint16_t    scid   = getenv("SAT_SCID") ? (uint16_t)strtoul(getenv("SAT_SCID"), NULL, 0) : SAT_SCID_SAT1;
    const char *bundle = getenv("SAT_BUNDLE") ? getenv("SAT_BUNDLE") : (scid == 0x102 ? "sat2" : "sat1");

    Sat_CoreInit(&sat, scid, tx, lg, NULL, NULL);
    /* Neighbours: SAT_ISL_PEERS="0x101:/path/key,0x103:/path/key2" (the key path may be
     * empty for a clear link), SAT_GS_PEER=<scid> the neighbour toward the ground station.
     * The older single neighbour form SAT_ISL_PEER, SAT_ISL_KEY, SAT_GS_VIA_ISL still works. */
    {
        char  spec[512] = "";
        char *tok, *save = NULL;
        uint16_t gsPeer = getenv("SAT_GS_PEER") ? (uint16_t)strtoul(getenv("SAT_GS_PEER"), NULL, 0) : 0;
        if (getenv("SAT_ISL_PEERS"))
        {
            snprintf(spec, sizeof spec, "%s", getenv("SAT_ISL_PEERS"));
        }
        else if (getenv("SAT_ISL_PEER"))
        {
            snprintf(spec, sizeof spec, "%s:%s", getenv("SAT_ISL_PEER"), getenv("SAT_ISL_KEY") ? getenv("SAT_ISL_KEY") : "");
            if (getenv("SAT_GS_VIA_ISL")) gsPeer = (uint16_t)strtoul(getenv("SAT_ISL_PEER"), NULL, 0);
        }
        if (spec[0])
        {
            Sat_SetIsl(&sat, isl_tx);
            for (tok = strtok_r(spec, ",", &save); tok; tok = strtok_r(NULL, ",", &save))
            {
                uint8_t  key[32];
                bool     have = false;
                char    *colon = strchr(tok, ':');
                uint16_t peer  = (uint16_t)strtoul(tok, NULL, 0);
                if (colon && colon[1])
                {
                    FILE *f = fopen(colon + 1, "rb");
                    if (f) { have = fread(key, 1, 32, f) == 32; fclose(f); }
                    if (!have) lg("ISL: key file unreadable, link in clear", NULL);
                }
                Sat_AddIslPeer(&sat, peer, peer == gsPeer, have ? key : NULL);
                memset(key, 0, sizeof key);
            }
        }
    }
    if (getenv("SAT_TX_PACE_PCT")) sat.txPaceMs = (uint32_t)atoi(getenv("SAT_TX_PACE_PCT"));
    if (getenv("SAT_LORA_SF")) Sat_SetLoraSf((unsigned)atoi(getenv("SAT_LORA_SF")));
    if (getenv("SAT_RX_WINDOW_MS")) sat.rxWindowMs = (uint32_t)atoi(getenv("SAT_RX_WINDOW_MS"));
    if (getenv("SAT_AUTH_EXTERNAL"))
    {
        g_external = 1;
        Sat_SetAuthRx(&sat, auth_rx);
        lg("auth: external satellite role (harness)", NULL);
    }
    else if (dir)
    {
        char path[512];
        int  r;
        Auth_Init(&auth, auth_send, lg, NULL);
        Auth_SetSessionHook(&auth, on_session);
        snprintf(path, sizeof path, "%s/%s.bundle", dir, bundle);
        r = Auth_LoadBundle(&auth, path);
        snprintf(path, sizeof path, "%s/gs.cert", dir);
        if (r == 0) r = Auth_LoadPeerCert(&auth, path);
        snprintf(path, sizeof path, "%s/ue1.cert", dir);
        if (r == 0 && getenv("SAT_AUTH_PRELOAD_UE")) r = Auth_LoadUserCert(&auth, path);
        if (getenv("SAT_AUTH_CRL")) (void)Auth_LoadCrl(&auth, getenv("SAT_AUTH_CRL"));
        if (getenv("SAT_AUTH_REF")) auth.full_certs = false;
        if (getenv("SAT_AUTH_FRESH_S")) Auth_SetFresh(&auth, (uint32_t)atoi(getenv("SAT_AUTH_FRESH_S")));
        if (r == 0)
        {
            char b[80];
            snprintf(b, sizeof b, "auth: %d satellite certificates loaded for end to end key transfer",
                     Auth_LoadSatCerts(&auth, &peers, dir));
            lg(b, NULL);
            sat.xferBuild = Auth_XferBuildHook;
            sat.xferOpen  = Auth_XferOpenHook;
            sat.xferCtx   = &xctx;
        }
        if (r == 0) { Sat_SetAuthRx(&sat, auth_rx); lg("auth: provisioned", NULL); }
        else { lg("auth: provisioning failed", NULL); }
    }
    while (fgets(line, sizeof line, stdin))
    {
        char *nl = strchr(line, '\n'); if (nl) *nl = 0;
        if (line[0] == 'C' && line[1] == ',')
        {
            g_now = (uint32_t)strtoul(line + 2, NULL, 10);
            Sat_OnRxHeartbeat(&sat, g_now);
            Sat_Tick(&sat, g_now);
            Auth_Tick(&auth, Sat_NowSec(&sat));
        }
        else if (line[0] == 'A' && line[1] == ',')
        {
            /* external role: A,<dst hex>,<message hex> */
            static uint8_t m[SAT_BIGTM_MAX];
            uint16_t dst = (uint16_t)strtoul(line + 2, NULL, 16);
            const char *hx = strchr(line + 2, ',');
            if (hx) { int n = unhex(hx + 1, m, SAT_BIGTM_MAX); Sat_SendAuth(&sat, dst, m, n); }
        }
        else if (line[0] == 'K' && line[1] == ',')
        {
            uint8_t sk[32];
            if (unhex(line + 2, sk, 32) == 32 && !getenv("SAT_NO_SDLS")) Sat_SdlsStart(&sat, sk);
        }
        else if (line[0] == 'I' && line[1] == ',')
        {
            /* I,<hex>: a frame from a neighbour (the sender's SCID in the frame says which) */
            uint8_t buf[SAT_MAX_FRAME];
            int     n = unhex(line + 2, buf, SAT_MAX_FRAME);
            Sat_OnIsl(&sat, buf, n, g_now);
        }
        else if (line[0] == 'R' && line[1] == ',')
        {
            char *p = line + 2, *e;
            int rssi = (int)strtol(p, &e, 10); p = e + 1;
            int snr  = (int)strtol(p, &e, 10); p = e + 1;
            g_now    = (uint32_t)strtoul(p, &e, 10); p = e + 1;
            {
                uint8_t buf[SAT_MAX_FRAME];
                int     n = unhex(p, buf, SAT_MAX_FRAME);
                Sat_OnUplink(&sat, buf, n, rssi, snr, g_now);
            }
        }
        printf("OK\n"); fflush(stdout);
    }
    return 0;
}
