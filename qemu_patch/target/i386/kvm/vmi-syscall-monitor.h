/*
 * Phase 6 inline syscall monitor (VMI research tool, catalog/library/nginx
 * vmi_syscall_monitor project). Fully opt-in via the VMI_MONITOR_ADDR
 * environment variable at QEMU startup -- when unset, every function here
 * is a no-op / returns false, and kvm_handle_debug()'s hot path is
 * byte-for-byte identical to stock QEMU. VMI_MONITOR_RET_ADDR (Phase 8)
 * additionally enables return-value capture; when it is unset the
 * monitor logs at syscall entry only, exactly as in Phase 6/7. Existing
 * gdbstub-based debugging is untouched and can still be used normally
 * (this monitor only ever acts on int3 hits at its own configured
 * addresses, in its own state).
 */
#ifndef VMI_SYSCALL_MONITOR_H
#define VMI_SYSCALL_MONITOR_H

typedef enum VmiState {
    VMI_NORMAL = 0,
    VMI_STEPPING,
} VmiState;

/* Call once, early in kvm_arch_init(). Reads VMI_MONITOR_ADDR /
 * VMI_MONITOR_LOG from the environment. No-op (monitor stays disabled)
 * if VMI_MONITOR_ADDR is unset. */
void vmi_monitor_init(void);

bool vmi_monitor_is_enabled(void);
target_ulong vmi_monitor_addr(void);

/* True iff the monitor is enabled and `pc` is one of its hook addresses:
 * the syscall entry (VMI_MONITOR_ADDR) or, if configured, the syscall
 * return point (VMI_MONITOR_RET_ADDR, Phase 8). */
bool vmi_monitor_is_hook_addr(target_ulong pc);

VmiState vmi_monitor_get_state(CPUState *cs);
void vmi_monitor_set_state(CPUState *cs, VmiState state);

/* Called from kvm_handle_debug() when: this cpu is in VMI_NORMAL and
 * vmi_monitor_is_hook_addr(pc) is true for the int3 that just trapped.
 * Synchronizes registers, records the syscall entry (or, at the return
 * hook, pairs it with its pending entry and logs it with its return
 * value), removes the breakpoint at `pc`, arms single-step, and
 * transitions the cpu to VMI_STEPPING. */
void vmi_monitor_breakpoint_hit(X86CPU *cpu, target_ulong pc);

/* Called from kvm_handle_debug() when: monitor enabled, this cpu is in
 * VMI_STEPPING, and the current trap is a single-step-completion (dr6
 * DR6_BS bit set). Disarms single-step, reinserts the breakpoint (with
 * readback verification) at whichever hook address it stepped over, and
 * transitions the cpu back to VMI_NORMAL. */
void vmi_monitor_step_complete(CPUState *cs);

/*
 * Phase 7: called from hw/nvram/fw_cfg.c's fw_cfg_dma_transfer(), exactly
 * once, right after the FW_CFG_KERNEL_DATA transfer that lands Unikraft's
 * kernel image in guest RAM has finished -- i.e. before the guest (the
 * multiboot option ROM) is allowed to run another instruction. This is
 * the one point in boot where writing 0xcc to vmi_monitor_addr() is
 * guaranteed not to be silently overwritten later (see
 * docs/phase7_boot_sync_investigation.md for why). No-op if the monitor
 * is disabled or a breakpoint is already confirmed live (via this path
 * or a real hit). `cs` is the vCPU that triggered the fw_cfg DMA access
 * (current_cpu at the fw_cfg.c call site).
 *
 * fw_cfg.c is generic/cross-architecture, so it forward-declares this
 * function itself with an `extern` rather than including this
 * x86/kvm-specific header (which pulls in X86CPU/CPUX86State) -- keep
 * this declaration's signature in sync with that forward declaration.
 */
void vmi_monitor_kernel_loaded(CPUState *cs);

#endif /* VMI_SYSCALL_MONITOR_H */
