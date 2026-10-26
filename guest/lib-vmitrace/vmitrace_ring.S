/* SPDX-License-Identifier: BSD-3-Clause */
/*
 * Zero-initialized vmitrace storage (struct vmitrace_lcpu_state[] followed by
 * the record rings, see include/vmitrace/abi.h). Defined in assembly so the
 * section is guaranteed @nobits: a C object in a custom-named section would
 * be emitted as PROGBITS and inflate the image.
 *
 * The `.bss.` prefix makes the common linker script's `*(.bss.*)` place it
 * inside .bss, i.e. before `_end` and inside the RW PT_LOAD that mkbootinfo
 * reserves as kernel memory. (A separate output section added with
 * `INSERT AFTER .bss` ended up after `_end`.)
 */

#include <uk/config.h>

#define VT_STATE_SIZE	64
#define VT_REC_SIZE	96
#define VT_CAPACITY	(1 << CONFIG_LIBVMITRACE_RING_ORDER)
#define VT_NR_LCPU	CONFIG_UKPLAT_LCPU_MAXCOUNT

.section .bss.vmitrace_ring, "aw", @nobits
.balign 4096

.globl vmitrace_ring_start
vmitrace_ring_start:

.globl vmitrace_state
.type vmitrace_state, @object
.size vmitrace_state, VT_STATE_SIZE * VT_NR_LCPU
vmitrace_state:
	.space VT_STATE_SIZE * VT_NR_LCPU

.balign 64
.globl vmitrace_records
.type vmitrace_records, @object
.size vmitrace_records, VT_REC_SIZE * VT_CAPACITY * VT_NR_LCPU
vmitrace_records:
	.space VT_REC_SIZE * VT_CAPACITY * VT_NR_LCPU

.globl vmitrace_ring_end
vmitrace_ring_end:
