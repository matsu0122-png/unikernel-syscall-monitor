/* SPDX-License-Identifier: BSD-3-Clause */
/* Hook code in one contiguous range, so the manifest can hash it. */
SECTIONS
{
	.vmitrace_text :
	{
		PROVIDE(vmitrace_text_start = .);
		*(.vmitrace_text)
		PROVIDE(vmitrace_text_end = .);
	}
}
INSERT AFTER .text;
