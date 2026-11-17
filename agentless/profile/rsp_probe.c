/* rsp_probe.c: minimal C client for QEMU's gdbstub, to split the cost of one
 * trap stop (Phase 11 overhead analysis). Not a monitor: one site only.
 *
 *   rsp_probe --port P --site S --target T [--exit E] --mode null|read|ret
 *
 *   null  per hit: g, P rip=target, c               (floor. P alone is not
 *         applied without a prior register read: the guest re-hits the site)
 *   pnull per hit: p10 (rip only), P, c
 *   --spin 1: busy-poll the socket instead of blocking (no wakeup our side)
 *   read  per hit: g, m r12+0x40,0x48, P, c         (vmi_trap.py --no-ret)
 *   ret   entry: g, m, Z0 exit, P, c; exit: g, z0 exit, c   (vmi_trap.py)
 *
 * The gdbstub must already listen (HMP gdbserver). SIGINT: stop, remove the
 * traps, detach, print JSON statistics (per-command round trips, time from
 * stop reply to `c`) to stdout.
 */
#define _GNU_SOURCE
#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

static int fd;
static volatile sig_atomic_t stopping;
static char rbuf[1 << 16];
static size_t rlen;
static int ack = 1;
static int spin;
static int waiting_stop;

enum { C_G, C_M, C_P, C_Z, C_ZR, C_C, C_N };
static const char *cname[C_N] = {"g", "m", "P", "Z0", "z0", "c_send"};
#define MAXS 400000
static double *samp[C_N];
static long ns_[C_N];
static double *hand_entry, *hand_exit;
static long n_entry, n_exit;

static double now_us(void)
{
	struct timespec t;
	clock_gettime(CLOCK_MONOTONIC, &t);
	return t.tv_sec * 1e6 + t.tv_nsec / 1e3;
}

static void die(const char *m)
{
	perror(m);
	exit(1);
}

static void send_pkt(const char *p)
{
	char out[1024];
	unsigned cs = 0;
	for (const char *q = p; *q; q++)
		cs += (unsigned char)*q;
	int n = snprintf(out, sizeof out, "$%s#%02x", p, cs & 0xff);
	if (write(fd, out, n) != n)
		die("write");
}

/* one packet payload into dst (NUL terminated); acks it if needed */
static int recv_pkt(char *dst, size_t cap)
{
	for (;;) {
		size_t i = 0;
		while (i < rlen && (rbuf[i] == '+' || rbuf[i] == '-'))
			i++;
		if (i) {
			memmove(rbuf, rbuf + i, rlen - i);
			rlen -= i;
		}
		char *s = memchr(rbuf, '$', rlen);
		if (s) {
			char *h = memchr(s, '#', rlen - (s - rbuf));
			if (h && (size_t)(h - rbuf) + 3 <= rlen) {
				size_t n = h - s - 1;
				if (n >= cap)
					n = cap - 1;
				memcpy(dst, s + 1, n);
				dst[n] = 0;
				size_t used = h - rbuf + 3;
				memmove(rbuf, rbuf + used, rlen - used);
				rlen -= used;
				if (ack && write(fd, "+", 1) != 1)
					die("ack");
				return 0;
			}
		}
		/* Ctrl-C only while the guest runs (waiting for a stop): sent
		 * while it is stopped, it is dropped and no stop ever comes */
		if (stopping == 1 && waiting_stop) {
			stopping = 2;
			if (write(fd, "\x03", 1) != 1)
				die("intr");
		}
		ssize_t r = read(fd, rbuf + rlen, sizeof rbuf - rlen);
		if (r < 0 && (errno == EINTR || (errno == EAGAIN && spin)))
			continue;
		if (r <= 0)
			return -1;
		rlen += r;
	}
}

static char reply[1 << 14];

static void cmd(int k, const char *p)
{
	double t0 = now_us();
	send_pkt(p);
	if (recv_pkt(reply, sizeof reply) < 0)
		die("recv");
	double d = now_us() - t0;
	if (k >= 0 && ns_[k] < MAXS)
		samp[k][ns_[k]++] = d;
}

static void cont(void)
{
	double t0 = now_us();
	send_pkt("c");
	if (ns_[C_C] < MAXS)
		samp[C_C][ns_[C_C]++] = now_us() - t0;
}

static uint64_t hex_le64(const char *h)
{
	uint64_t v = 0;
	for (int i = 7; i >= 0; i--) {
		unsigned b;
		sscanf(h + 2 * i, "%2x", &b);
		v = v << 8 | b;
	}
	return v;
}

static void le64_hex(uint64_t v, char *out)
{
	for (int i = 0; i < 8; i++)
		sprintf(out + 2 * i, "%02x", (unsigned)(v >> (8 * i)) & 0xff);
}

static int cmpd(const void *a, const void *b)
{
	double x = *(const double *)a, y = *(const double *)b;
	return (x > y) - (x < y);
}

static void print_dist(const char *name, double *v, long n, int last)
{
	double sum = 0;
	for (long i = 0; i < n; i++)
		sum += v[i];
	qsort(v, n, sizeof *v, cmpd);
	printf("  \"%s\": {\"n\": %ld, \"mean_us\": %.1f, \"p50_us\": %.1f, \"p90_us\": %.1f}%s\n",
	       name, n, n ? sum / n : 0, n ? v[n / 2] : 0, n ? v[n * 9 / 10] : 0,
	       last ? "" : ",");
}

static void on_int(int s)
{
	(void)s;
	if (!stopping)
		stopping = 1;
}

int main(int argc, char **argv)
{
	int port = 0;
	uint64_t site = 0, target = 0, exit_site = 0;
	const char *mode = "null";
	for (int i = 1; i + 1 < argc; i += 2) {
		if (!strcmp(argv[i], "--port"))
			port = atoi(argv[i + 1]);
		else if (!strcmp(argv[i], "--site"))
			site = strtoull(argv[i + 1], 0, 0);
		else if (!strcmp(argv[i], "--target"))
			target = strtoull(argv[i + 1], 0, 0);
		else if (!strcmp(argv[i], "--exit"))
			exit_site = strtoull(argv[i + 1], 0, 0);
		else if (!strcmp(argv[i], "--spin"))
			spin = atoi(argv[i + 1]);
		else if (!strcmp(argv[i], "--mode"))
			mode = argv[i + 1];
	}
	int m_null = !strcmp(mode, "null") || !strcmp(mode, "pnull"), m_ret = !strcmp(mode, "ret");
	if (!port || !site || !target || (m_ret && !exit_site)) {
		fprintf(stderr, "usage: see source\n");
		return 2;
	}
	for (int k = 0; k < C_N; k++)
		samp[k] = malloc(MAXS * sizeof(double));
	hand_entry = malloc(MAXS * sizeof(double));
	hand_exit = malloc(MAXS * sizeof(double));

	struct sigaction sa = {.sa_handler = on_int}; /* no SA_RESTART: read gets EINTR */
	sigaction(SIGINT, &sa, 0);
	sigaction(SIGTERM, &sa, 0);

	fd = socket(AF_INET, SOCK_STREAM, 0);
	struct sockaddr_in a = {.sin_family = AF_INET, .sin_port = htons(port)};
	inet_pton(AF_INET, "127.0.0.1", &a.sin_addr);
	if (connect(fd, (void *)&a, sizeof a))
		die("connect");
	int one = 1;
	setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof one);

	/* QEMU stops the guest on connect and sends the stop (T02) unasked */
	struct timeval tv = {1, 0};
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	recv_pkt(reply, sizeof reply);
	tv.tv_sec = 0;
	setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof tv);
	cmd(-1, "QStartNoAckMode");
	if (!strcmp(reply, "OK"))
		ack = 0;
	cmd(-1, "qSupported:xmlRegisters=i386");
	for (unsigned off = 0;;) { /* P is refused until target.xml is read */
		char q[64];
		snprintf(q, sizeof q, "qXfer:features:read:target.xml:%x,800", off);
		cmd(-1, q);
		off += strlen(reply) - 1;
		if (reply[0] == 'l')
			break;
		if (reply[0] != 'm')
			die("target.xml");
	}
	char p[256], h[17];
	snprintf(p, sizeof p, "Z0,%lx,1", (unsigned long)site);
	cmd(-1, p);
	if (strcmp(reply, "OK"))
		die("Z0 site");
	if (spin) {
		int nb = 1;
		ioctl(fd, FIONBIO, &nb);
	}
	fprintf(stderr, "rsp_probe: mode %s, site %#lx armed, ack %d\n", mode,
		(unsigned long)site, ack);
	send_pkt("c");

	long stops = 0, foreign = 0;
	int exit_armed = 0;
	char zexit[64], rzexit[64];
	snprintf(zexit, sizeof zexit, "Z0,%lx,1", (unsigned long)exit_site);
	snprintf(rzexit, sizeof rzexit, "z0,%lx,1", (unsigned long)exit_site);
	double t_start = now_us();
	for (;;) {
		waiting_stop = 1;
		int rc = recv_pkt(reply, sizeof reply);
		waiting_stop = 0;
		if (rc < 0)
			die("stop");
		double t0 = now_us();
		if (reply[0] != 'T' && reply[0] != 'S')
			break;
		if (stopping)
			break;
		stops++;
		if (m_null) {
			cmd(C_G, mode[0] == 'p' ? "p10" : "g");
			le64_hex(target, h);
			snprintf(p, sizeof p, "P10=%s", h);
			cmd(C_P, p);
			cont();
			hand_entry[n_entry++ % MAXS] = now_us() - t0;
			continue;
		}
		cmd(C_G, "g");
		uint64_t rip = hex_le64(reply + 16 * 16);
		uint64_t rsp_ = hex_le64(reply + 7 * 16);
		uint64_t r12 = hex_le64(reply + 12 * 16);
		(void)rsp_;
		if (rip == site) {
			snprintf(p, sizeof p, "m%lx,48", (unsigned long)(r12 + 0x40));
			cmd(C_M, p);
			if (m_ret && !exit_armed) {
				cmd(C_Z, zexit);
				exit_armed = 1;
			}
			le64_hex(target, h);
			snprintf(p, sizeof p, "P10=%s", h);
			cmd(C_P, p);
			cont();
			if (n_entry < MAXS)
				hand_entry[n_entry++] = now_us() - t0;
		} else if (m_ret && rip == exit_site && exit_armed) {
			cmd(C_ZR, rzexit);
			exit_armed = 0;
			cont();
			if (n_exit < MAXS)
				hand_exit[n_exit++] = now_us() - t0;
		} else {
			foreign++;
			cont();
		}
	}
	double wall = now_us() - t_start;
	snprintf(p, sizeof p, "z0,%lx,1", (unsigned long)site);
	cmd(-1, p);
	if (exit_armed)
		cmd(-1, rzexit);
	send_pkt("D");
	recv_pkt(reply, sizeof reply);
	close(fd);

	printf("{\n  \"mode\": \"%s\", \"spin\": %d, \"stops\": %ld, \"foreign\": %ld, \"wall_s\": %.3f,\n",
	       mode, spin, stops, foreign, wall / 1e6);
	for (int k = 0; k < C_N; k++)
		print_dist(cname[k], samp[k], ns_[k], 0);
	print_dist("handling_entry", hand_entry, n_entry, 0);
	print_dist("handling_exit", hand_exit, n_exit, 1);
	printf("}\n");
	return 0;
}
