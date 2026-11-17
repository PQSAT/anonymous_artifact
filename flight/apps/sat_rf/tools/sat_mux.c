/* sat_mux: share one serial line between the two satellite instances on the Versal.
 *
 * The laptop bridge talks to the Versal over one UART.  With two satellites on
 * the board (cpu1 = SAT-1, cpu2 = SAT-2) each cFS instance needs its own
 * radio line, so this program owns the UART and offers one pseudo terminal per
 * satellite:
 *
 *     bridge <-UART-> sat_mux <-pty-> /tmp/sat1.tty  (SAT_RF_DEVICE of cpu1)
 *                             <-pty-> /tmp/sat2.tty  (SAT_RF_DEVICE of cpu2)
 *
 * Line protocol: lines for SAT-2 carry the prefix "2:" in both directions;
 * SAT-1 lines are unchanged, so a bridge that knows one satellite still works.
 *
 *     sat_mux /dev/ttyAMA0 /tmp/sat1.tty /tmp/sat2.tty
 */
#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <termios.h>
#include <unistd.h>

#define LINE_MAX_LEN 1024

typedef struct
{
    int  fd;
    char buf[LINE_MAX_LEN];
    int  len;
} Port_t;

static int open_uart(const char *dev)
{
    struct termios t;
    int            fd = open(dev, O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (fd < 0)
    {
        return -1;
    }
    tcgetattr(fd, &t);
    cfmakeraw(&t);
    cfsetispeed(&t, B115200);
    cfsetospeed(&t, B115200);
    t.c_cflag |= CLOCAL | CREAD;
    tcsetattr(fd, TCSANOW, &t);
    return fd;
}

static int open_pty(const char *link)
{
    struct termios t;
    int            m = posix_openpt(O_RDWR | O_NOCTTY | O_NONBLOCK);
    if (m < 0 || grantpt(m) < 0 || unlockpt(m) < 0)
    {
        return -1;
    }
    tcgetattr(m, &t);
    cfmakeraw(&t);
    tcsetattr(m, TCSANOW, &t);
    unlink(link);
    if (symlink(ptsname(m), link) < 0)
    {
        return -1;
    }
    return m;
}

static void write_all(int fd, const char *s, int n)
{
    int off = 0;
    while (off < n)
    {
        int w = (int)write(fd, s + off, (size_t)(n - off));
        if (w < 0)
        {
            if (errno == EAGAIN)
            {
                usleep(1000);
                continue;
            }
            return;
        }
        off += w;
    }
}

/* Deliver one complete line (without newline) from port `from`. */
static void on_line(int from, const char *line, int n, Port_t *uart, Port_t *sat1, Port_t *sat2)
{
    char out[LINE_MAX_LEN + 4];

    if (from == uart->fd)
    {
        if (n >= 2 && line[0] == '2' && line[1] == ':')
        {
            memcpy(out, line + 2, (size_t)(n - 2));
            out[n - 2] = '\n';
            write_all(sat2->fd, out, n - 1);
        }
        else
        {
            memcpy(out, line, (size_t)n);
            out[n] = '\n';
            write_all(sat1->fd, out, n + 1);
        }
    }
    else if (from == sat2->fd)
    {
        out[0] = '2';
        out[1] = ':';
        memcpy(out + 2, line, (size_t)n);
        out[n + 2] = '\n';
        write_all(uart->fd, out, n + 3);
    }
    else
    {
        memcpy(out, line, (size_t)n);
        out[n] = '\n';
        write_all(uart->fd, out, n + 1);
    }
}

static void pump(Port_t *p, Port_t *uart, Port_t *sat1, Port_t *sat2)
{
    char buf[512];
    int  n = (int)read(p->fd, buf, sizeof buf);
    int  i;

    if (n <= 0)
    {
        return;
    }
    for (i = 0; i < n; i++)
    {
        char c = buf[i];
        if (c == '\n' || c == '\r')
        {
            if (p->len > 0)
            {
                on_line(p->fd, p->buf, p->len, uart, sat1, sat2);
            }
            p->len = 0;
        }
        else if (p->len < LINE_MAX_LEN - 1)
        {
            p->buf[p->len++] = c;
        }
        else
        {
            p->len = 0; /* oversize line dropped */
        }
    }
}

int main(int argc, char **argv)
{
    Port_t        uart = {-1, {0}, 0}, sat1 = {-1, {0}, 0}, sat2 = {-1, {0}, 0};
    struct pollfd pf[3];

    if (argc != 4)
    {
        fprintf(stderr, "usage: sat_mux <uart> <sat1 link> <sat2 link>\n");
        return 2;
    }
    uart.fd = open_uart(argv[1]);
    sat1.fd = open_pty(argv[2]);
    sat2.fd = open_pty(argv[3]);
    if (uart.fd < 0 || sat1.fd < 0 || sat2.fd < 0)
    {
        perror("sat_mux open");
        return 1;
    }
    for (;;)
    {
        int i;
        pf[0].fd = uart.fd;
        pf[1].fd = sat1.fd;
        pf[2].fd = sat2.fd;
        for (i = 0; i < 3; i++)
        {
            pf[i].events = POLLIN;
        }
        if (poll(pf, 3, 1000) <= 0)
        {
            continue;
        }
        if (pf[0].revents & POLLIN) pump(&uart, &uart, &sat1, &sat2);
        if (pf[1].revents & POLLIN) pump(&sat1, &uart, &sat1, &sat2);
        if (pf[2].revents & POLLIN) pump(&sat2, &uart, &sat1, &sat2);
    }
}
