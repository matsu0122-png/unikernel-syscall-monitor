/* SPDX-License-Identifier: BSD-3-Clause */
/* Constant header, page-aligned, in the read-only segment. */
SECTIONS
{
	. = ALIGN(0x1000);
	.vmitrace :
	{
		PROVIDE(vmitrace_hdr_start = .);
		KEEP(*(.vmitrace))
		PROVIDE(vmitrace_hdr_end = .);
	}
}
INSERT AFTER .rodata;
