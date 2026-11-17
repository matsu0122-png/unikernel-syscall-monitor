/*
 * libvmitrap.so: baked-trap handling inside an unmodified QEMU (Phase 11-3).
 *
 *   LD_PRELOAD=agentless/kvmtrap/libvmitrap.so VMI_KVMTRAP_CONF=<conf> \
 *       /usr/bin/qemu-system-x86_64 ...
 *
 * Started by agentless/qemu-kvmtrap.sh; the conf, the reference bytes and
 * the record ring are written by agentless/kvmtrap/kvmtrap.py, which also
 * reads the ring and writes JSONL / OTel. Nothing is added to the guest
 * beyond the 0xCCs agentless/bake_traps.py put in the image, and the QEMU
 * binary is the distro one: this library interposes libc's ioctl() and acts
 * only at the KVM ioctl boundary.
 *
 * - KVM_RUN: the vCPU's KVM_RUN is re-issued here in a loop. A
 *   KVM_EXIT_DEBUG for #BP at a baked site is handled without returning to
 *   QEMU: no VM stop, no gdbstub, no single-step. Everything else
 *   (I/O, MMIO, signals, a #BP that is not ours) goes back to QEMU as is;
 *   QEMU re-injects a foreign #BP into the guest.
 * - entry site (tail jmp of a selected syscall's case block): read nr and
 *   arguments from the saved registers (r12 -> guest stack, KVM_TRANSLATE),
 *   set rip to the jump target (KVM_SET_REGS). The 0xCC is never lifted.
 * - exit site (`mov %rax,disp8(%r12)` after `call uk_syscall6_do_e`): 0xCC
 *   written there only while a selected syscall is in flight; on a hit the
 *   one instruction is emulated (store rax, rip += 5), so no single-step.
 * - KVM_SET_GUEST_DEBUG: USE_SW_BP is set on every vCPU before its first
 *   KVM_RUN and OR-ed into any later call from QEMU.
 * - KVM_SET_USER_MEMORY_REGION: slots recorded to reach guest RAM directly.
 * - a check thread compares the dispatcher, jump table and caller with the
 *   image (armed 0xCCs overlaid) every check_ms and re-arms removed traps.
 *
 * Records go to a shared-memory ring (overwritten when the reader lags,
 * never blocking the vCPU).
 */
#define _GNU_SOURCE
#include <dlfcn.h>
#include <errno.h>
#include <fcntl.h>
#include <linux/kvm.h>
#include <pthread.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <time.h>
#include <unistd.h>

/* ------------------------------------------------------------ ring ABI */
/* Keep in sync with agentless/kvmtrap/kvmtrap.py */
#define RING_MAGIC "KVMTRAP1"
#define RING_HDR 4096

enum {
	K_SYSCALL = 1, K_SERVING = 2, K_ALERT = 3,
};
enum {	/* alert codes (rec.nr for K_ALERT) */
	A_TRAP_REMOVED = 1, A_CODE_MODIFIED, A_RESTORED, A_TRAP_REARMED,
	A_NR_MISMATCH, A_FOREIGN_TRAP, A_BOUNDARY_RETIRED, A_CODE_CHECK_FAILED,
	A_PENDING_OVERFLOW,
};
enum {	/* stats in the ring header */
	ST_STOPS, ST_ENTRIES, ST_EXITS, ST_UNMATCHED_EXITS, ST_NR_MISMATCH,
	ST_FOREIGN, ST_STARTUP_STOPS, ST_REARMED, ST_HANDLING_NS, ST_CHECKS,
	ST_CHECK_NS, ST_PENDING_OVERFLOW, ST_KVM_RUN_CALLS, ST_ALERTS,
	ST_SERVING_SINCE_NS, ST_RECORDS, NSTAT = 32
};

struct ring_hdr {
	char magic[8];
	uint32_t rec_size, pad;
	uint64_t nrec;
	uint64_t widx;			/* next slot to write (release) */
	uint64_t stats[NSTAT];
};

#define F_ENTRY_ONLY 1
struct krec {
	uint32_t kind, nr;
	uint64_t seq, t_enter, t_exit;
	uint64_t args[6];
	int64_t ret;
	uint64_t tid;
	uint32_t flags, region;
	uint64_t x[3];
};
_Static_assert(sizeof(struct krec) == 128, "krec size");

/* ------------------------------------------------------------ state */
#define MAX_SITES 512
#define MAX_REGIONS 4
#define MAX_SLOTS 64
#define MAX_VCPUS 16
#define MAX_PENDING 64

struct site {
	uint64_t addr, target;
	uint8_t orig, armed, entry;	/* entry: a selected syscall's site */
	int nnrs;
	uint32_t nrs[8];
};
struct region {
	char name[32];
	uint64_t addr, len, refoff;
	int16_t *bad;			/* last reported live byte, -1 = ok */
};
struct slot {
	uint32_t id;
	uint64_t gpa, size, hva;
};
struct vcpu {
	int fd;
	struct kvm_run *run;
	struct kvm_guest_debug qemu_dbg;	/* what QEMU last asked for */
};
struct pend {
	int used;
	uint64_t key;
	struct krec rec;
};

static int (*real_ioctl)(int, unsigned long, ...);
static int active;
static pthread_mutex_t mu = PTHREAD_MUTEX_INITIALIZER;
static FILE *logf;
static struct ring_hdr *ring;
static struct krec *recs;
static int kvm_fd = -1;
static long run_size;

static struct site sites[MAX_SITES];
static int nsites;
static struct region regions[MAX_REGIONS];
static int nregions;
static uint8_t *ref;
static size_t ref_len;
static struct slot slots[MAX_SLOTS];
static int nslots;
static struct vcpu vcpus[MAX_VCPUS];
static int nvcpus;
static struct pend pending[MAX_PENDING];
static int npending;

static int want_ret = 1, startup_skip = 1, fail_closed = 1;
static long check_ms = 1000;
static uint64_t off_orig_rax, off_args[6];	/* rdi rsi rdx r10 r8 r9 */
static uint64_t exit_site;
static uint8_t exit_orig, exit_disp, exit_len;
static int exit_armed;
static uint64_t serving_site, serving_target;
static uint8_t serving_orig;
static int serving_selected, have_serving, boundary_only;
static int serving, code_checked;
static uint64_t seq;

static void logm(const char *fmt, ...)
{
	if (!logf)
		return;
	struct timespec ts;
	clock_gettime(CLOCK_REALTIME, &ts);
	fprintf(logf, "[libvmitrap %ld.%06ld] ", (long)ts.tv_sec, ts.tv_nsec / 1000);
	va_list ap;
	va_start(ap, fmt);
	vfprintf(logf, fmt, ap);
	va_end(ap);
	fputc('\n', logf);
	fflush(logf);
}

static void die(const char *fmt, ...)
{
	char buf[512];
	va_list ap;
	va_start(ap, fmt);
	vsnprintf(buf, sizeof(buf), fmt, ap);
	va_end(ap);
	fprintf(stderr, "libvmitrap: %s\n", buf);
	logm("FATAL %s", buf);
	_exit(1);
}

static uint64_t now_ns(clockid_t c)
{
	struct timespec ts;
	clock_gettime(c, &ts);
	return (uint64_t)ts.tv_sec * 1000000000ull + ts.tv_nsec;
}

/* ------------------------------------------------------------ ring */
static void ring_put(const struct krec *r)	/* mu held */
{
	uint64_t w = ring->widx;
	recs[w % ring->nrec] = *r;
	__atomic_store_n(&ring->widx, w + 1, __ATOMIC_RELEASE);
	ring->stats[ST_RECORDS]++;
}

static void alert(uint32_t code, uint32_t region, uint64_t a, uint64_t b, uint64_t c)
{
	struct krec r = {0};
	r.kind = K_ALERT;
	r.nr = code;
	r.region = region;
	r.t_enter = r.t_exit = now_ns(CLOCK_REALTIME);
	r.x[0] = a;
	r.x[1] = b;
	r.x[2] = c;
	ring->stats[ST_ALERTS]++;
	ring_put(&r);
	logm("alert %u region %u %#lx %#lx %#lx", code, region,
	     (unsigned long)a, (unsigned long)b, (unsigned long)c);
}

/* ------------------------------------------------------------ guest memory */
static uint8_t *gpa2hva(uint64_t gpa, uint64_t len)
{
	for (int i = 0; i < nslots; i++)
		if (slots[i].size && gpa >= slots[i].gpa &&
		    gpa + len <= slots[i].gpa + slots[i].size)
			return (uint8_t *)(uintptr_t)(slots[i].hva + (gpa - slots[i].gpa));
	return NULL;
}

static int gva2gpa(int fd, uint64_t gva, uint64_t *gpa)
{
	struct kvm_translation t = {.linear_address = gva};
	if (real_ioctl(fd, KVM_TRANSLATE, &t) < 0 || !t.valid)
		return -1;
	*gpa = t.physical_address;
	return 0;
}

/* copy between guest-virtual memory and buf, page by page */
static int gva_rw(int fd, uint64_t gva, void *buf, size_t len, int write)
{
	uint8_t *b = buf;
	while (len) {
		uint64_t gpa, n = 4096 - (gva & 4095);
		if (n > len)
			n = len;
		if (gva2gpa(fd, gva, &gpa) < 0)
			return -1;
		uint8_t *h = gpa2hva(gpa, n);
		if (!h)
			return -1;
		if (write)
			memcpy(h, b, n);
		else
			memcpy(b, h, n);
		gva += n;
		b += n;
		len -= n;
	}
	return 0;
}

/* code bytes: identity-mapped image (virtual = physical), as with HMP xp */
static int code_write(uint64_t addr, uint8_t v)
{
	uint8_t *h = gpa2hva(addr, 1);
	if (!h)
		return -1;
	__atomic_store_n(h, v, __ATOMIC_SEQ_CST);
	return 0;
}

static struct site *find_site(uint64_t addr)
{
	int lo = 0, hi = nsites - 1;
	while (lo <= hi) {
		int m = (lo + hi) / 2;
		if (sites[m].addr == addr)
			return &sites[m];
		if (sites[m].addr < addr)
			lo = m + 1;
		else
			hi = m - 1;
	}
	return NULL;
}

/* ------------------------------------------------------------ code check */
static uint8_t expected_byte(uint64_t addr, uint8_t orig)
{
	struct site *s = find_site(addr);
	return s && s->armed ? 0xCC : orig;
}

/* mu held. initial: any difference is fatal (wrong image / modified before
 * the first syscall). Otherwise report changes and re-arm removed traps. */
static int check_regions(int initial)
{
	uint64_t t0 = now_ns(CLOCK_MONOTONIC);
	int bad_total = 0;
	for (int ri = 0; ri < nregions; ri++) {
		struct region *rg = &regions[ri];
		uint8_t *live = gpa2hva(rg->addr, rg->len);
		const uint8_t *orig = ref + rg->refoff;
		if (!live) {
			logm("region %s %#lx+%lu not in guest RAM", rg->name,
			     (unsigned long)rg->addr, (unsigned long)rg->len);
			return -1;
		}
		for (uint64_t i = 0; i < rg->len; i++) {
			uint64_t addr = rg->addr + i;
			if (addr == exit_site)
				continue;	/* volatile: armed only in flight */
			uint8_t got = live[i], want = expected_byte(addr, orig[i]);
			if (got == want) {
				if (rg->bad[i] >= 0) {
					alert(A_RESTORED, ri, addr, got, want);
					rg->bad[i] = -1;
				}
				continue;
			}
			bad_total++;
			if (initial) {
				if (bad_total <= 8)
					logm("initial check: %s %#lx live %#x want %#x",
					     rg->name, (unsigned long)addr, got, want);
				continue;
			}
			struct site *s = find_site(addr);
			int removed = s && s->armed;
			if (rg->bad[i] != got) {
				alert(removed ? A_TRAP_REMOVED : A_CODE_MODIFIED, ri, addr, got, want);
				rg->bad[i] = got;
			}
			if (removed) {
				code_write(addr, 0xCC);
				ring->stats[ST_REARMED]++;
				alert(A_TRAP_REARMED, ri, addr, live[i], 0xCC);
			}
		}
	}
	ring->stats[ST_CHECKS]++;
	ring->stats[ST_CHECK_NS] += now_ns(CLOCK_MONOTONIC) - t0;
	return bad_total;
}

static void *check_thread(void *arg)
{
	(void)arg;
	struct timespec d = {check_ms / 1000, (check_ms % 1000) * 1000000L};
	for (;;) {
		nanosleep(&d, NULL);
		pthread_mutex_lock(&mu);
		check_regions(0);
		pthread_mutex_unlock(&mu);
	}
	return NULL;
}

/* ------------------------------------------------------------ vCPU */
static struct vcpu *get_vcpu(int fd)	/* mu held */
{
	for (int i = 0; i < nvcpus; i++)
		if (vcpus[i].fd == fd)
			return &vcpus[i];
	if (nvcpus == MAX_VCPUS)
		die("too many vCPUs");
	struct vcpu *v = &vcpus[nvcpus++];
	memset(v, 0, sizeof(*v));
	v->fd = fd;
	return v;
}

static void apply_debug(struct vcpu *v)
{
	struct kvm_guest_debug d = v->qemu_dbg;
	d.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
	if (real_ioctl(v->fd, KVM_SET_GUEST_DEBUG, &d) < 0)
		die("KVM_SET_GUEST_DEBUG on vcpu fd %d: %s", v->fd, strerror(errno));
}

static void vcpu_init(struct vcpu *v)
{
	v->run = mmap(NULL, run_size, PROT_READ | PROT_WRITE, MAP_SHARED, v->fd, 0);
	if (v->run == MAP_FAILED)
		die("mmap kvm_run: %s", strerror(errno));
	apply_debug(v);
	logm("vcpu fd %d: sw breakpoints enabled", v->fd);
}

static void set_rip(int fd, struct kvm_regs *regs, uint64_t rip)
{
	regs->rip = rip;
	if (real_ioctl(fd, KVM_SET_REGS, regs) < 0)
		die("KVM_SET_REGS: %s", strerror(errno));
}

static void retire_boundary(struct site *s)
{
	code_write(s->addr, s->orig);
	s->armed = 0;
	alert(A_BOUNDARY_RETIRED, 0, s->addr, s->orig, 0);
}

static void start_serving(uint64_t t)
{
	serving = 1;
	ring->stats[ST_SERVING_SINCE_NS] = t;
	struct krec r = {0};
	r.kind = K_SERVING;
	r.t_enter = r.t_exit = t;
	r.x[0] = ring->stats[ST_STARTUP_STOPS];
	ring_put(&r);
	logm("first accept4: recording from here (%lu startup stops)",
	     (unsigned long)r.x[0]);
}

static void entry_hit(int fd, struct site *s, struct kvm_regs *regs, uint64_t t)
{
	uint8_t raw[0x48];
	struct krec r = {0};
	r.kind = K_SYSCALL;
	r.flags = F_ENTRY_ONLY;
	r.t_enter = t;
	r.tid = regs->r12;
	r.nr = s->nrs[0];
	if (gva_rw(fd, regs->r12 + 0x40, raw, sizeof(raw), 0) == 0) {
		uint64_t v;
		memcpy(&v, raw + off_orig_rax - 0x40, 8);
		int ok = 0;
		for (int i = 0; i < s->nnrs; i++)
			if (s->nrs[i] == v) {
				ok = 1;
				r.nr = (uint32_t)v;
			}
		if (!ok) {
			ring->stats[ST_NR_MISMATCH]++;
			alert(A_NR_MISMATCH, 0, s->addr, v, s->nrs[0]);
		}
		for (int i = 0; i < 6; i++)
			memcpy(&r.args[i], raw + off_args[i] - 0x40, 8);
	} else {
		r.flags |= 2;	/* arguments unreadable */
	}
	r.seq = seq++;
	ring->stats[ST_ENTRIES]++;
	if (!want_ret) {
		ring_put(&r);
		return;
	}
	struct pend *p = NULL;
	for (int i = 0; i < MAX_PENDING; i++)
		if (!pending[i].used) {
			p = &pending[i];
			break;
		}
	if (!p) {			/* emit entry-only rather than block */
		ring->stats[ST_PENDING_OVERFLOW]++;
		ring_put(&r);
		return;
	}
	p->used = 1;
	p->key = regs->rsp;
	p->rec = r;
	npending++;
	if (!exit_armed) {
		code_write(exit_site, 0xCC);
		exit_armed = 1;
	}
}

static void exit_hit(int fd, struct kvm_regs *regs, uint64_t t)
{
	/* emulate `mov %rax, disp8(%r12)` */
	uint64_t rax = regs->rax;
	if (gva_rw(fd, regs->r12 + exit_disp, &rax, 8, 1) < 0)
		die("exit emulation: r12 %#lx not writable", (unsigned long)regs->r12);
	struct pend *p = NULL;
	for (int i = 0; i < MAX_PENDING; i++)
		if (pending[i].used && pending[i].key == regs->rsp - 8) {
			p = &pending[i];
			break;
		}
	if (p) {
		p->rec.ret = (int64_t)regs->rax;
		p->rec.t_exit = t;
		p->rec.flags &= ~F_ENTRY_ONLY;
		ring_put(&p->rec);
		p->used = 0;
		npending--;
		ring->stats[ST_EXITS]++;
	} else {
		ring->stats[ST_UNMATCHED_EXITS]++;
	}
	if (!npending) {
		code_write(exit_site, exit_orig);
		exit_armed = 0;
	}
	set_rip(fd, regs, regs->rip + exit_len);
}

/* 1: handled here, re-enter the guest; 0: give the exit to QEMU */
static int handle_bp(struct vcpu *v)
{
	uint64_t t0 = now_ns(CLOCK_MONOTONIC), t = now_ns(CLOCK_REALTIME);
	uint64_t pc = v->run->debug.arch.pc;
	int handled = 1;

	pthread_mutex_lock(&mu);
	struct site *s = find_site(pc);
	int ours = (s && s->armed) || (pc == exit_site && exit_armed);
	if (!ours) {
		ring->stats[ST_FOREIGN]++;
		alert(A_FOREIGN_TRAP, 0, pc, 0, 0);
		pthread_mutex_unlock(&mu);
		return 0;
	}
	if (!code_checked) {
		code_checked = 1;
		int bad = check_regions(1);
		if (bad) {
			alert(A_CODE_CHECK_FAILED, 0, pc, (uint64_t)bad, 0);
			if (fail_closed)
				die("guest code differs from the image at the first trap "
				    "(%d bytes); refusing", bad);
		}
		logm("first trap at %#lx: guest code matches the image", (unsigned long)pc);
		if (check_ms > 0) {
			pthread_t th;
			if (pthread_create(&th, NULL, check_thread, NULL))
				die("pthread_create");
			pthread_detach(th);
		}
	}
	ring->stats[ST_STOPS]++;

	struct kvm_regs regs;
	if (real_ioctl(v->fd, KVM_GET_REGS, &regs) < 0)
		die("KVM_GET_REGS: %s", strerror(errno));

	if (pc == exit_site && exit_armed) {
		exit_hit(v->fd, &regs, t);
		goto out;
	}
	if (have_serving && pc == serving_site) {
		if (!serving)
			start_serving(t);
		if (boundary_only) {
			retire_boundary(s);
			set_rip(v->fd, &regs, serving_target);
			goto out;
		}
	}
	if (!serving) {
		ring->stats[ST_STARTUP_STOPS]++;
		set_rip(v->fd, &regs, s->target);
		goto out;
	}
	if (s->entry) {
		entry_hit(v->fd, s, &regs, t);
		set_rip(v->fd, &regs, s->target);
	} else {
		handled = 0;	/* cannot happen: only entries and the boundary are sites */
	}
out:
	ring->stats[ST_HANDLING_NS] += now_ns(CLOCK_MONOTONIC) - t0;
	pthread_mutex_unlock(&mu);
	return handled;
}

static int kvm_run(int fd, void *arg)
{
	pthread_mutex_lock(&mu);
	struct vcpu *v = get_vcpu(fd);
	if (!v->run)
		vcpu_init(v);
	pthread_mutex_unlock(&mu);
	for (;;) {
		int r = real_ioctl(fd, KVM_RUN, arg);
		__atomic_fetch_add(&ring->stats[ST_KVM_RUN_CALLS], 1, __ATOMIC_RELAXED);
		if (r != 0 || v->run->exit_reason != KVM_EXIT_DEBUG ||
		    v->run->debug.arch.exception != 3 /* #BP */)
			return r;
		if (!handle_bp(v))
			return r;
	}
}

/* ------------------------------------------------------------ interposer */
int ioctl(int fd, unsigned long req, ...)
{
	va_list ap;
	va_start(ap, req);
	void *arg = va_arg(ap, void *);
	va_end(ap);
	if (!real_ioctl)
		real_ioctl = dlsym(RTLD_NEXT, "ioctl");
	if (!active)
		return real_ioctl(fd, req, arg);

	switch (req) {
	case KVM_RUN:
		return kvm_run(fd, arg);
	case KVM_SET_GUEST_DEBUG: {
		pthread_mutex_lock(&mu);
		struct vcpu *v = get_vcpu(fd);
		v->qemu_dbg = *(struct kvm_guest_debug *)arg;
		struct kvm_guest_debug d = v->qemu_dbg;
		d.control |= KVM_GUESTDBG_ENABLE | KVM_GUESTDBG_USE_SW_BP;
		pthread_mutex_unlock(&mu);
		logm("QEMU set guest debug %#x on fd %d (kept USE_SW_BP)",
		     ((struct kvm_guest_debug *)arg)->control, fd);
		return real_ioctl(fd, req, &d);
	}
	case KVM_SET_USER_MEMORY_REGION: {
		int r = real_ioctl(fd, req, arg);
		if (r == 0) {
			struct kvm_userspace_memory_region *m = arg;
			pthread_mutex_lock(&mu);
			int i;
			for (i = 0; i < nslots; i++)
				if (slots[i].id == m->slot)
					break;
			if (i == nslots) {
				if (nslots == MAX_SLOTS)
					die("too many memory slots");
				nslots++;
			}
			slots[i] = (struct slot){m->slot, m->guest_phys_addr,
						 m->memory_size, m->userspace_addr};
			pthread_mutex_unlock(&mu);
		}
		return r;
	}
	}
	return real_ioctl(fd, req, arg);
}

/* ------------------------------------------------------------ setup */
static void parse_conf(const char *path)
{
	FILE *f = fopen(path, "r");
	if (!f)
		die("conf %s: %s", path, strerror(errno));
	char line[1024], ring_path[512] = "", ref_path[512] = "", log_path[512] = "";
	int have_regs = 0, have_exit = 0;
	while (fgets(line, sizeof(line), f)) {
		char k[32];
		if (sscanf(line, "%31s", k) != 1 || k[0] == '#')
			continue;
		const char *rest = line + strlen(k);
		if (!strcmp(k, "ring"))
			sscanf(rest, "%511s", ring_path);
		else if (!strcmp(k, "ref"))
			sscanf(rest, "%511s", ref_path);
		else if (!strcmp(k, "log"))
			sscanf(rest, "%511s", log_path);
		else if (!strcmp(k, "want_ret"))
			sscanf(rest, "%d", &want_ret);
		else if (!strcmp(k, "startup_skip"))
			sscanf(rest, "%d", &startup_skip);
		else if (!strcmp(k, "fail_closed"))
			sscanf(rest, "%d", &fail_closed);
		else if (!strcmp(k, "check_ms"))
			sscanf(rest, "%ld", &check_ms);
		else if (!strcmp(k, "regs")) {
			unsigned long o[7];
			if (sscanf(rest, "%lu %lu %lu %lu %lu %lu %lu", &o[0], &o[1], &o[2],
				   &o[3], &o[4], &o[5], &o[6]) != 7)
				die("conf: bad regs line");
			off_orig_rax = o[0];
			for (int i = 0; i < 6; i++)
				off_args[i] = o[i + 1];
			for (int i = 0; i < 7; i++)
				if (o[i] < 0x40 || o[i] + 8 > 0x88)
					die("conf: register offset %lu outside 0x40..0x88", o[i]);
			have_regs = 1;
		} else if (!strcmp(k, "exit")) {
			unsigned long a;
			unsigned o, d, l;
			if (sscanf(rest, "%lx %x %x %u", &a, &o, &d, &l) != 4)
				die("conf: bad exit line");
			exit_site = a;
			exit_orig = o;
			exit_disp = d;
			exit_len = l;
			have_exit = 1;
		} else if (!strcmp(k, "serving")) {
			unsigned long a, t;
			unsigned o;
			int sel, baked;
			if (sscanf(rest, "%lx %lx %x %d %d", &a, &t, &o, &sel, &baked) != 5)
				die("conf: bad serving line");
			serving_site = a;
			serving_target = t;
			serving_orig = o;
			serving_selected = sel;
			have_serving = 1;
			boundary_only = !sel && baked;
			if (!sel && baked) {	/* the unselected boundary is a baked site */
				if (nsites == MAX_SITES)
					die("too many sites");
				struct site *s = &sites[nsites++];
				memset(s, 0, sizeof(*s));
				s->addr = a;
				s->target = t;
				s->orig = o;
				s->armed = 1;
			}
		} else if (!strcmp(k, "site")) {
			if (nsites == MAX_SITES)
				die("too many sites");
			struct site *s = &sites[nsites++];
			memset(s, 0, sizeof(*s));
			unsigned long a, t;
			unsigned o;
			int n, used;
			if (sscanf(rest, "%lx %lx %x %d%n", &a, &t, &o, &n, &used) != 4 ||
			    n < 1 || n > 8)
				die("conf: bad site line");
			s->addr = a;
			s->target = t;
			s->orig = o;
			s->armed = 1;
			s->entry = 1;
			s->nnrs = n;
			const char *p = rest + used;
			for (int i = 0; i < n; i++) {
				int u;
				if (sscanf(p, "%u%n", &s->nrs[i], &u) != 1)
					die("conf: bad site nrs");
				p += u;
			}
		} else if (!strcmp(k, "region")) {
			if (nregions == MAX_REGIONS)
				die("too many regions");
			struct region *rg = &regions[nregions++];
			unsigned long a, l, o;
			if (sscanf(rest, "%31s %lx %lu %lu", rg->name, &a, &l, &o) != 4)
				die("conf: bad region line");
			rg->addr = a;
			rg->len = l;
			rg->refoff = o;
		} else {
			die("conf: unknown key %s", k);
		}
	}
	fclose(f);
	if (!*ring_path || !*ref_path || !have_regs || !have_exit || !nsites)
		die("conf %s incomplete", path);
	if (startup_skip && !have_serving)
		die("conf: startup_skip without a serving boundary");
	if (!startup_skip)
		serving = 1;

	if (*log_path)
		logf = fopen(log_path, "a");

	/* sites sorted for binary search; no duplicates */
	for (int i = 1; i < nsites; i++)
		for (int j = i; j > 0 && sites[j - 1].addr > sites[j].addr; j--) {
			struct site t = sites[j];
			sites[j] = sites[j - 1];
			sites[j - 1] = t;
		}
	for (int i = 1; i < nsites; i++)
		if (sites[i].addr == sites[i - 1].addr)
			die("conf: duplicate site %#lx", (unsigned long)sites[i].addr);

	int fd = open(ref_path, O_RDONLY);
	struct stat st;
	if (fd < 0 || fstat(fd, &st) < 0)
		die("ref %s: %s", ref_path, strerror(errno));
	ref_len = st.st_size;
	ref = malloc(ref_len);
	if (!ref || read(fd, ref, ref_len) != (ssize_t)ref_len)
		die("ref %s: short read", ref_path);
	close(fd);
	for (int i = 0; i < nregions; i++) {
		if (regions[i].refoff + regions[i].len > ref_len)
			die("region %s beyond the ref file", regions[i].name);
		regions[i].bad = malloc(regions[i].len * sizeof(int16_t));
		for (uint64_t j = 0; j < regions[i].len; j++)
			regions[i].bad[j] = -1;
	}

	fd = open(ring_path, O_RDWR);
	if (fd < 0 || fstat(fd, &st) < 0)
		die("ring %s: %s", ring_path, strerror(errno));
	ring = mmap(NULL, st.st_size, PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	close(fd);
	if (ring == MAP_FAILED)
		die("mmap ring: %s", strerror(errno));
	if (memcmp(ring->magic, RING_MAGIC, 8) || ring->rec_size != sizeof(struct krec) ||
	    RING_HDR + ring->nrec * sizeof(struct krec) > (uint64_t)st.st_size)
		die("ring %s: bad header", ring_path);
	recs = (struct krec *)((char *)ring + RING_HDR);

	logm("conf %s: %d sites, exit %#lx, want_ret %d, startup_skip %d, check_ms %ld",
	     path, nsites, (unsigned long)exit_site, want_ret, startup_skip, check_ms);
}

__attribute__((constructor)) static void libvmitrap_init(void)
{
	real_ioctl = dlsym(RTLD_NEXT, "ioctl");
	if (!real_ioctl) {
		fprintf(stderr, "libvmitrap: no ioctl in libc\n");
		_exit(1);
	}
	const char *conf = getenv("VMI_KVMTRAP_CONF");
	if (!conf || !*conf)
		return;		/* loaded but not configured: pass everything through */
	parse_conf(conf);
	kvm_fd = open("/dev/kvm", O_RDWR | O_CLOEXEC);
	if (kvm_fd < 0)
		die("/dev/kvm: %s", strerror(errno));
	run_size = real_ioctl(kvm_fd, KVM_GET_VCPU_MMAP_SIZE, 0);
	if (run_size <= 0)
		die("KVM_GET_VCPU_MMAP_SIZE");
	active = 1;
}
