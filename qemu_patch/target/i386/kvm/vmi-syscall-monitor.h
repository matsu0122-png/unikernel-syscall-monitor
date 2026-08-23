/*
 * Phase 6 inline syscall monitor (VMI research tool, catalog/library/nginx
 * vmi_syscall_monitor project). Fully opt-in via the VMI_MONITOR_ADDR
 * environment variable at QEMU startup -- when unset, every function here
 * is a no-op / returns false, and kvm_handle_debug()'s hot path is
 * byte-for-byte identical to stock QEMU. Existing gdbstub-based debugging
 * is untouched and can still be used normally (this monitor only ever
 * acts on int3 hits at its own configured address, in its own state).
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

VmiState vmi_monitor_get_state(CPUState *cs);
void vmi_monitor_set_state(CPUState *cs, VmiState state);

/* Called from kvm_handle_debug() when: monitor enabled, this cpu is in
 * VMI_NORMAL, and the int3 that just trapped is at vmi_monitor_addr().
 * Synchronizes registers, logs the syscall, removes the breakpoint, arms
 * single-step, and transitions the cpu to VMI_STEPPING. */
void vmi_monitor_breakpoint_hit(X86CPU *cpu);

/* Called from kvm_handle_debug() when: monitor enabled, this cpu is in
 * VMI_STEPPING, and the current trap is a single-step-completion (dr6
 * DR6_BS bit set). Disarms single-step, reinserts the breakpoint (with
 * readback verification), and transitions the cpu back to VMI_NORMAL. */
void vmi_monitor_step_complete(CPUState *cs);

#endif /* VMI_SYSCALL_MONITOR_H */
