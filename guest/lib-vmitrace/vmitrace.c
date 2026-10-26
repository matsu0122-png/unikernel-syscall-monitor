/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * vmitrace: record selected binary syscalls into a guest-RAM ring buffer
 * that the host reads through a shared memory-backend-file. No VM exit,
 * no blocking: a full ring overwrites its oldest record.
 *
 * Hooks are registered with syscall_shim's enter/exit tables
 * (uk_syscall_entertab_prio / uk_syscall_exittab_prio), so Unikraft itself
 * is unmodified. Layout and write protocol: include/vmitrace/abi.h.
 */

#include <uk/config.h>
#include <uk/essentials.h>
#include <uk/prio.h>
#include <uk/syscall.h>
#include <uk/arch/lcpu.h>
#include <uk/plat/lcpu.h>
#include <uk/plat/time.h>
#if CONFIG_LIBPOSIX_PROCESS
#include <uk/process.h>
#endif /* CONFIG_LIBPOSIX_PROCESS */

#include <vmitrace/abi.h>
#include "groups.h"
#include "vmitrace_nonce.h"	/* generated, see Makefile.uk */

#define VT_CAPACITY	(1UL << CONFIG_LIBVMITRACE_RING_ORDER)
#define VT_NR_LCPU	CONFIG_UKPLAT_LCPU_MAXCOUNT
/* Entry timestamps kept per thread, indexed by syscall nesting depth.
 * Binary syscalls don't nest, so only slot 0 is used in practice.
 */
#define VT_MAX_DEPTH	4

#define __vt_text	__section(".vmitrace_text")

UK_CTASSERT(sizeof(struct vmitrace_hdr) == 64);
UK_CTASSERT(sizeof(struct vmitrace_lcpu_state) == 64);
UK_CTASSERT(sizeof(struct vmitrace_rec) == 96);

/* Storage in the NOBITS .bss.vmitrace_ring section (vmitrace_ring.S) */
extern struct vmitrace_lcpu_state vmitrace_state[VT_NR_LCPU];
extern struct vmitrace_rec vmitrace_records[VT_NR_LCPU][VT_CAPACITY];

/*
 * 512-bit selection bitmap, computed at compile time from the
 * LIBVMITRACE_GROUP_* options. Lives in .rodata; the hooks read it through
 * a volatile pointer so the in-memory copy (which the integrity checker
 * hashes) is what actually decides, not a constant folded into the code.
 */
#define VT_BIT(name, w)							\
	| (((SYS_##name) >> 6) == (w) ? (1ULL << ((SYS_##name) & 63)) : 0ULL)

#if CONFIG_LIBVMITRACE_GROUP_ALL
#define VT_WORD(w)	(~0ULL)
#else /* !CONFIG_LIBVMITRACE_GROUP_ALL */
#if CONFIG_LIBVMITRACE_GROUP_NET || CONFIG_LIBVMITRACE_GROUP_NETFD
#define VT_NET(w)	VMITRACE_GROUP_NET(VT_BIT, w)
#else
#define VT_NET(w)
#endif
#if CONFIG_LIBVMITRACE_GROUP_NETFD
#define VT_NETFD(w)	VMITRACE_GROUP_NETFD_EXTRA(VT_BIT, w)
#else
#define VT_NETFD(w)
#endif
#if CONFIG_LIBVMITRACE_GROUP_FILE
#define VT_FILE(w)	VMITRACE_GROUP_FILE(VT_BIT, w)
#else
#define VT_FILE(w)
#endif
#if CONFIG_LIBVMITRACE_GROUP_TIME
#define VT_TIME(w)	VMITRACE_GROUP_TIME(VT_BIT, w)
#else
#define VT_TIME(w)
#endif
#define VT_WORD(w)	(0ULL VT_NET(w) VT_NETFD(w) VT_FILE(w) VT_TIME(w))
#endif /* !CONFIG_LIBVMITRACE_GROUP_ALL */

__used __align64
const __u64 vmitrace_bitmap[VMITRACE_BITMAP_WORDS] = {
	VT_WORD(0), VT_WORD(1), VT_WORD(2), VT_WORD(3),
	VT_WORD(4), VT_WORD(5), VT_WORD(6), VT_WORD(7),
};

__used __section(".vmitrace")
const struct vmitrace_hdr vmitrace_hdr = {
	.magic        = VMITRACE_MAGIC,
	.version      = VMITRACE_VERSION,
	.record_size  = sizeof(struct vmitrace_rec),
	.capacity     = VT_CAPACITY,
	.nr_lcpu      = VT_NR_LCPU,
	.state_addr   = (__u64)(__uptr)vmitrace_state,
	.records_addr = (__u64)(__uptr)vmitrace_records,
	.bitmap_addr  = (__u64)(__uptr)vmitrace_bitmap,
	.build_nonce  = { VMITRACE_BUILD_NONCE0, VMITRACE_BUILD_NONCE1 },
};

static __thread __u64 vt_enter_ts[VT_MAX_DEPTH];

static inline __vt_text int vt_selected(__u64 nr)
{
	const volatile __u64 *bm = vmitrace_bitmap;

	if (unlikely(nr >= VMITRACE_BITMAP_BITS))
		return 0;
	return (bm[nr >> 6] >> (nr & 63)) & 1;
}

static inline __vt_text __u64 vt_tid(__u16 *flags)
{
#if CONFIG_LIBPOSIX_PROCESS
	pid_t tid = uk_sys_gettid();

	if (unlikely(tid < 0))
		*flags |= VMITRACE_F_TID_ERR;
	return (__u64)(__s64)tid;
#else /* !CONFIG_LIBPOSIX_PROCESS */
	(void)flags;
	return 0;
#endif /* !CONFIG_LIBPOSIX_PROCESS */
}

static __vt_text void vt_write(const struct ukarch_execenv *execenv,
			       __u16 flags, __u64 ts_enter, __u64 ts_exit,
			       __s64 ret)
{
	__lcpuidx lcpu = ukplat_lcpu_idx();
	struct vmitrace_lcpu_state *st = &vmitrace_state[lcpu];
	__u64 idx = st->write_idx;
	struct vmitrace_rec *r = &vmitrace_records[lcpu][idx & (VT_CAPACITY - 1)];
	__u64 tid = vt_tid(&flags);

	r->seq = 0;
	barrier();
	r->ts_enter_ns = ts_enter;
	r->ts_exit_ns  = ts_exit;
	r->nr          = (__u32)execenv->regs.__syscall_rsyscall;
	r->lcpu        = (__u16)lcpu;
	r->flags       = flags;
	r->args[0]     = execenv->regs.__syscall_rarg0;
	r->args[1]     = execenv->regs.__syscall_rarg1;
	r->args[2]     = execenv->regs.__syscall_rarg2;
	r->args[3]     = execenv->regs.__syscall_rarg3;
	r->args[4]     = execenv->regs.__syscall_rarg4;
	r->args[5]     = execenv->regs.__syscall_rarg5;
	r->ret         = ret;
	r->tid         = tid;
	barrier();
	r->seq = idx + 1;
	barrier();
	st->write_idx = idx + 1;
}

static __vt_text void vt_enter(struct uk_syscall_enter_ctx *ctx)
{
	struct ukarch_execenv *execenv = ctx->execenv;
	unsigned long depth = ctx->nested_depth;
	__u64 nr, now;

	/* Native calls from inside Unikraft run this table too, with
	 * execenv == NULL and no BINARY flag (lib/syscall_shim/tabs.c).
	 */
	if (!(ctx->flags & UK_SYSCALL_ENTER_CTX_BINARY_SYSCALL) || !execenv)
		return;

	nr = execenv->regs.__syscall_rsyscall;
	if (!vt_selected(nr))
		return;

	now = ukplat_monotonic_clock();
	if (likely(depth >= 1 && depth <= VT_MAX_DEPTH))
		vt_enter_ts[depth - 1] = now;

	/* These never reach the exit table */
	if (unlikely(nr == SYS_exit || nr == SYS_exit_group))
		vt_write(execenv, VMITRACE_F_ENTRY_ONLY, now, 0, 0);
}

static __vt_text void vt_exit(struct uk_syscall_exit_ctx *ctx)
{
	struct ukarch_execenv *execenv = ctx->execenv;
	unsigned long depth = ctx->nested_depth;
	__u64 ts_enter = 0, now;
	__u16 flags = 0;

	if (!(ctx->flags & UK_SYSCALL_EXIT_CTX_BINARY_SYSCALL) || !execenv)
		return;

	if (!vt_selected(execenv->regs.__syscall_rsyscall))
		return;

	now = ukplat_monotonic_clock();
	if (likely(depth >= 1 && depth <= VT_MAX_DEPTH)) {
		ts_enter = vt_enter_ts[depth - 1];
		vt_enter_ts[depth - 1] = 0;
	}
	if (unlikely(!ts_enter))
		flags |= VMITRACE_F_NO_ENTER_TS;

	vt_write(execenv, flags, ts_enter, now,
		 (__s64)execenv->regs.__syscall_rret0);
}

uk_syscall_entertab_prio(vt_enter, UK_PRIO_EARLIEST);
uk_syscall_exittab_prio(vt_exit, UK_PRIO_LATEST);
