/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * vmitrace shared-memory layout, version 1.
 *
 * This is the contract between the guest writer (vmitrace.c) and the
 * host-side readers (collector/, integrity/). The host maps guest RAM
 * through a memory-backend-file and treats every byte below as untrusted
 * input.
 *
 * Two regions, both at link-time-constant guest physical addresses
 * (Unikraft maps the image 1:1):
 *
 *   .vmitrace       PROGBITS  struct vmitrace_hdr, initialized in the image.
 *                             Never written at run time, so the host can
 *                             hash it against the manifest.
 *   .bss.vmitrace_ring        struct vmitrace_lcpu_state[nr_lcpu], then
 *         (NOBITS, in .bss)   nr_lcpu rings of `capacity` records each.
 *                             Zero-filled by the loader before the first
 *                             guest instruction.
 *
 * Record protocol (one writer per ring = per lcpu, no atomics):
 *   1. rec->seq = 0                    (invalidate the slot)
 *   2. compiler barrier
 *   3. write all other fields
 *   4. compiler barrier
 *   5. rec->seq = idx + 1
 *   6. compiler barrier
 *   7. state->write_idx = idx + 1
 * x86 keeps stores in program order (TSO), so a reader that sees
 * seq == idx + 1 before and after copying the record has a complete copy.
 */

#ifndef __VMITRACE_ABI_H__
#define __VMITRACE_ABI_H__

#include <uk/arch/types.h>

#define VMITRACE_MAGIC		0x4543415254494d56ULL	/* "VMITRACE" */
#define VMITRACE_VERSION	1

#define VMITRACE_BITMAP_BITS	512
#define VMITRACE_BITMAP_WORDS	(VMITRACE_BITMAP_BITS / 64)

/* vmitrace_rec.flags */
#define VMITRACE_F_ENTRY_ONLY	(1 << 0) /* written at entry (exit/exit_group);
					  * ts_exit_ns and ret are 0 */
#define VMITRACE_F_NO_ENTER_TS	(1 << 1) /* entry time not available */
#define VMITRACE_F_TID_ERR	(1 << 2) /* tid holds a -errno from gettid */

struct vmitrace_hdr {
	__u64 magic;		/*  0 */
	__u32 version;		/*  8 */
	__u32 record_size;	/* 12 */
	__u32 capacity;		/* 16 records per lcpu, power of two */
	__u32 nr_lcpu;		/* 20 */
	__u64 state_addr;	/* 24 GPA of vmitrace_lcpu_state[0] */
	__u64 records_addr;	/* 32 GPA of ring 0, record 0 */
	__u64 bitmap_addr;	/* 40 GPA of the 512-bit syscall bitmap */
	__u64 reserved[2];	/* 48 */
};				/* 64 */

/* One per lcpu, 64 bytes so lcpus never share a cache line. */
struct vmitrace_lcpu_state {
	__u64 write_idx;	/*  0 records ever written, monotonic */
	__u64 dropped;		/*  8 events the guest could not record */
	__u64 reserved[6];	/* 16 */
};				/* 64 */

struct vmitrace_rec {
	__u64 seq;		/*  0 idx + 1, written last; 0 = in progress */
	__u64 ts_enter_ns;	/*  8 ukplat_monotonic_clock() at entry */
	__u64 ts_exit_ns;	/* 16 ukplat_monotonic_clock() at exit */
	__u32 nr;		/* 24 */
	__u16 lcpu;		/* 28 */
	__u16 flags;		/* 30 VMITRACE_F_* */
	__u64 args[6];		/* 32 */
	__s64 ret;		/* 80 */
	__u64 tid;		/* 88 */
};				/* 96 */

#endif /* __VMITRACE_ABI_H__ */
