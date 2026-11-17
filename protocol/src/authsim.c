/* authsim.c  -  the C satellite role as a line process, for interoperability
 * testing against the Python user and ground station with no link in between.
 *
 *   in:  M,<from hex4>,<now seconds>,<message hex>
 *        T,<now seconds>                 (tick)
 *        Q                                (print counters and exit)
 *   out: S,<dst hex4>,<message hex>
 *        LOG,<text>
 *        OK                               after every input line
 */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "sat_auth.h"

static void send(uint16_t dst, const uint8_t *m, int n, void *ctx)
{
    int i;
    (void)ctx;
    printf("S,%04X,", dst);
    for (i = 0; i < n; i++)
    {
        printf("%02X", m[i]);
    }
    printf("\n");
}

static void lg(const char *m, void *ctx)
{
    (void)ctx;
    printf("LOG,%s\n", m);
}

int main(int argc, char **argv)
{
    static Auth_Sat_t a;
    static char       line[2 * 32768 + 64];
    static uint8_t    buf[32768];
    int               r;

    if (argc < 3)
    {
        fprintf(stderr, "usage: authsim <sat bundle> <gs cert>\n");
        return 2;
    }
    Auth_Init(&a, send, lg, NULL);
    if ((r = Auth_LoadBundle(&a, argv[1])) != 0)
    {
        fprintf(stderr, "bundle load failed %d\n", r);
        return 1;
    }
    if ((r = Auth_LoadPeerCert(&a, argv[2])) != 0)
    {
        fprintf(stderr, "ground certificate load failed %d\n", r);
        return 1;
    }
    if (argc > 3 && strcmp(argv[3], "ref") == 0)
    {
        a.full_certs = false;
    }
    if (argc > 4 && Auth_LoadUserCert(&a, argv[4]) != 0)
    {
        fprintf(stderr, "user certificate load failed\n");
        return 1;
    }
    printf("LOG,satellite %04X ready, ground %04X\n", a.ident, a.id_gs);
    fflush(stdout);

    while (fgets(line, sizeof line, stdin))
    {
        char *nl = strchr(line, '\n');
        if (nl)
        {
            *nl = 0;
        }
        if (line[0] == 'M')
        {
            char    *p = line + 2, *e;
            uint16_t from = (uint16_t)strtoul(p, &e, 16);
            uint32_t now;
            size_t   hl, i, n;
            p   = e + 1;
            now = (uint32_t)strtoul(p, &e, 10);
            p   = e + 1;
            hl  = strlen(p);
            n   = hl / 2;
            if (n > sizeof buf)
            {
                n = sizeof buf;
            }
            for (i = 0; i < n; i++)
            {
                char t[3] = {p[2 * i], p[2 * i + 1], 0};
                buf[i]    = (uint8_t)strtoul(t, NULL, 16);
            }
            Auth_OnMessage(&a, from, buf, (int)n, now);
        }
        else if (line[0] == 'T')
        {
            Auth_Tick(&a, (uint32_t)strtoul(line + 2, NULL, 10));
        }
        else if (line[0] == 'Q')
        {
            printf("STAT,ok=%u,failed=%u,rejected=%u,replays=%u,demands=%u,kem_us=%.0f,sign_us=%.0f,"
                   "verify_us=%.0f,cert_us=%.0f,wrap_us=%.0f\n",
                   a.handshakes_ok, a.handshakes_failed, a.messages_rejected, a.replays_rejected, a.demands_sent,
                   a.t_kem_us, a.t_sign_us, a.t_verify_us, a.t_cert_us, a.t_wrap_us);
            if (a.have_sk)
            {
                int i;
                printf("SK,");
                for (i = 0; i < 32; i++)
                {
                    printf("%02x", a.sk[i]);
                }
                printf("\n");
            }
            fflush(stdout);
            return 0;
        }
        printf("OK\n");
        fflush(stdout);
    }
    return 0;
}
