/*
 * Phase 6 inline syscall monitor. See vmi-syscall-monitor.h for the
 * opt-in contract. Design background:
 * catalog/library/nginx/1.25/vmi_syscall_monitor/docs/phase6_inline_qemu_design.md
 */
#include "qemu/osdep.h"
#include "qemu/error-report.h"
#include "qemu/timer.h"
#include "qemu/main-loop.h"
#include "sysemu/runstate.h"
#include "sysemu/hw_accel.h"
#include "sysemu/kvm.h"
#include "exec/gdbstub.h"
#include "cpu.h"

#include "vmi-syscall-monitor.h"
#include "vmi-syscall-table.h"

static bool vmi_enabled;
static target_ulong vmi_addr;
static FILE *vmi_log_fp;
static FILE *vmi_debug_fp; /* diagnostics; survives -daemonize (unlike stderr) */
static GHashTable *vmi_state_table; /* CPUState* -> VmiState (direct value) */
static QEMUTimer *vmi_arm_timer;
static int vmi_arm_attempts;
static bool vmi_first_hit_seen;
static bool vmi_boot_sync_ok; /* Phase 7: true once vmi_monitor_kernel_loaded() armed successfully */

#define VMI_ARM_RETRY_MS      200
#define VMI_ARM_MAX_ATTEMPTS  100 /* ~20s total before giving up */

/*
 * Diagnostics go through this instead of error_report()/warn_report()/
 * info_report() alone: kraftkit runs QEMU with -daemonize, which
 * redirects stdin/stdout/stderr to /dev/null once the process forks into
 * the background -- so anything written only to stderr after that point
 * is silently lost with no way to observe arm attempts/failures from
 * outside. This file is opened once at vmi_monitor_init() time (before
 * daemonize) and stays open, so writes to it land reliably regardless of
 * daemonize timing.
 */
static void vmi_debug(const char *fmt, ...)
{
    va_list ap;

    if (!vmi_debug_fp) {
        return;
    }
    va_start(ap, fmt);
    vfprintf(vmi_debug_fp, fmt, ap);
    va_end(ap);
    fputc('\n', vmi_debug_fp);
    fflush(vmi_debug_fp);
}

bool vmi_monitor_is_enabled(void)
{
    return vmi_enabled;
}

target_ulong vmi_monitor_addr(void)
{
    return vmi_addr;
}

VmiState vmi_monitor_get_state(CPUState *cs)
{
    if (!vmi_state_table) {
        return VMI_NORMAL;
    }
    return (VmiState)(uintptr_t)g_hash_table_lookup(vmi_state_table, cs);
}

void vmi_monitor_set_state(CPUState *cs, VmiState state)
{
    g_hash_table_insert(vmi_state_table, cs, (gpointer)(uintptr_t)state);
}

/*
 * Core, single-attempt arm-and-verify: remove any stale registration,
 * insert fresh, read the byte back and require exactly 0xcc. Shared by
 * both the Phase 6 timer-retry path (vmi_try_arm(), below) and the
 * Phase 7 boot-sync path (vmi_monitor_kernel_loaded()) -- the readback
 * requirement is the direct fix for the Phase 5 failure mode:
 * kvm_insert_breakpoint() reporting success is NOT sufficient evidence
 * that 0xcc actually landed in guest memory. `log_tag` is just the
 * bracketed prefix used in vmi_debug() lines (e.g. "arm" or
 * "boot-sync") so the two callers' attempts stay distinguishable in
 * <log>.debug.log.
 *
 * Always removes before inserting, even on the very first attempt
 * (where this is a harmless -ENOENT no-op): kvm_insert_breakpoint() on
 * an address it already believes is registered just increments a
 * refcount and returns 0 WITHOUT touching guest memory -- so calling it
 * again after an external revert would silently do nothing. This
 * remove+insert pair is what actually forces a fresh memory patch.
 */
static bool vmi_arm_once(CPUState *cs, const char *log_tag)
{
    uint8_t readback;
    int err;

    kvm_remove_breakpoint(cs, vmi_addr, 1, GDB_BREAKPOINT_SW);

    err = kvm_insert_breakpoint(cs, vmi_addr, 1, GDB_BREAKPOINT_SW);
    if (err) {
        vmi_debug("[%s] kvm_insert_breakpoint(0x%" PRIx64 ") failed: %d",
                  log_tag, (uint64_t)vmi_addr, err);
        return false;
    }

    if (cpu_memory_rw_debug(cs, vmi_addr, &readback, 1, 0) != 0) {
        vmi_debug("[%s] verification read itself failed -- address "
                  "translation likely not established yet", log_tag);
        kvm_remove_breakpoint(cs, vmi_addr, 1, GDB_BREAKPOINT_SW);
        return false;
    }

    if (readback != 0xcc) {
        vmi_debug("[%s] readback=0x%02x, NOT 0xcc (Phase 5-style silent "
                  "failure)", log_tag, readback);
        kvm_remove_breakpoint(cs, vmi_addr, 1, GDB_BREAKPOINT_SW);
        return false;
    }

    vmi_debug("[%s] readback=0xcc confirmed", log_tag);
    return true;
}

/*
 * Phase 6 fallback path: poll every 200ms. Empirically (this project's
 * boot path: QEMU pre-stages the kernel image via -kernel/-initrd, but
 * the guest actually boots through SeaBIOS -> iPXE -> chainload, not a
 * direct jump to the kernel entry point) a breakpoint armed at the very
 * first RUN_STATE_RUNNING transition can read back as genuinely 0xcc at
 * that instant and then be silently overwritten later in the same boot
 * sequence (observed directly: readback was 0xcc right after arming,
 * but 0xfa -- the original byte -- a few seconds later once boot had
 * progressed, confirmed via a plain HMP `xp` read with no monitor code
 * involved). Root-caused in Phase 7
 * (docs/phase7_boot_sync_investigation.md): a single one-shot
 * fw_cfg_dma_transfer() call overwrites this region once, at an
 * unpredictable point in boot. vmi_monitor_kernel_loaded() (below) now
 * hooks that exact event instead of guessing -- this polling loop stays
 * only as a fallback for whenever that hook doesn't end up firing (or
 * this build's boot path changes), and immediately stands down
 * (vmi_boot_sync_ok) the moment the hook succeeds.
 */
static void vmi_try_arm(void *opaque)
{
    CPUState *cs = first_cpu;

    if (vmi_first_hit_seen || vmi_boot_sync_ok) {
        /* Either a real hit, or the Phase 7 boot-sync hook, already
         * proved the breakpoint is live; nothing left to do (this can
         * still be invoked once more if a retry was already in flight
         * when that happened). */
        if (vmi_arm_timer) {
            timer_free(vmi_arm_timer);
            vmi_arm_timer = NULL;
        }
        return;
    }

    vmi_arm_attempts++;
    vmi_debug("[arm] attempt %d/%d: re-arming (remove-then-insert) at 0x%"
              PRIx64, vmi_arm_attempts, VMI_ARM_MAX_ATTEMPTS,
              (uint64_t)vmi_addr);

    if (!vmi_arm_once(cs, "arm")) {
        warn_report("vmi-monitor: arm attempt %d/%d at 0x%" PRIx64
                     " did not stick -- retrying in %d ms",
                     vmi_arm_attempts, VMI_ARM_MAX_ATTEMPTS,
                     (uint64_t)vmi_addr, VMI_ARM_RETRY_MS);
        goto retry_or_fail;
    }

    info_report("vmi-monitor: breakpoint armed and VERIFIED at 0x%" PRIx64
                " (0xcc confirmed via memory readback; attempt %d/%d; "
                "still monitoring for revert until first real hit)",
                (uint64_t)vmi_addr, vmi_arm_attempts, VMI_ARM_MAX_ATTEMPTS);
    /* Do NOT stop here: a successful readback is not proof the
     * breakpoint survives the rest of boot on this fallback path (that
     * guarantee only holds for the boot-sync path). Keep the timer
     * running; it self-cancels once vmi_first_hit_seen or
     * vmi_boot_sync_ok is set. */
    if (vmi_arm_attempts >= VMI_ARM_MAX_ATTEMPTS) {
        vmi_debug("[arm] reached max attempts while still re-verifying; "
                  "leaving last-known-good state and giving up on further "
                  "checks (breakpoint may or may not still be live)");
        error_report("vmi-monitor: gave up re-verifying breakpoint at 0x%"
                     PRIx64 " after %d attempts without ever observing a "
                     "real hit -- capture may be silently inactive.",
                     (uint64_t)vmi_addr, vmi_arm_attempts);
        if (vmi_arm_timer) {
            timer_free(vmi_arm_timer);
            vmi_arm_timer = NULL;
        }
        return;
    }
    timer_mod(vmi_arm_timer,
              qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + VMI_ARM_RETRY_MS);
    return;

retry_or_fail:
    if (vmi_arm_attempts >= VMI_ARM_MAX_ATTEMPTS) {
        vmi_debug("[arm] giving up after %d attempts", vmi_arm_attempts);
        error_report("vmi-monitor: FAILED to arm breakpoint at 0x%" PRIx64
                     " after %d attempts over ~%d ms -- syscall capture is "
                     "NOT active. Guest continues to run unmonitored.",
                     (uint64_t)vmi_addr, vmi_arm_attempts,
                     vmi_arm_attempts * VMI_ARM_RETRY_MS);
        if (vmi_arm_timer) {
            timer_free(vmi_arm_timer);
            vmi_arm_timer = NULL;
        }
        return;
    }
    timer_mod(vmi_arm_timer,
              qemu_clock_get_ms(QEMU_CLOCK_REALTIME) + VMI_ARM_RETRY_MS);
}

/*
 * Phase 7: called from fw_cfg_dma_transfer() (hw/nvram/fw_cfg.c) the
 * instant the FW_CFG_KERNEL_DATA transfer -- the one event that writes
 * Unikraft's kernel image into guest RAM -- has finished, and before
 * that function returns control to the guest. See
 * docs/phase7_boot_sync_investigation.md for the full derivation of why
 * this specific point is safe and no explicit vCPU pause is needed: we
 * are already executing synchronously on the same call stack as the
 * guest's own triggering MMIO write, so there is no window for another
 * guest instruction to run between "kernel bytes just landed" and "our
 * 0xcc is in place".
 *
 * BQL note (checked empirically, not assumed -- see
 * qemu_mutex_iothread_locked() call below and its corresponding
 * [boot-sync] debug line): kvm_cpu_exec()'s KVM_EXIT_MMIO case is
 * explicitly commented "Called outside BQL", and
 * memory_region_dispatch_write() (softmmu/memory.c) does not acquire it
 * either -- so unlike vmi_try_arm() (always called from a timer
 * callback or a vm-state-change notifier, both BQL-guaranteed by QEMU
 * itself), this function cannot assume the BQL is already held. It is
 * taken explicitly here if not already held, mirroring the same
 * pattern kvm_arch_handle_exit()'s KVM_EXIT_DEBUG case already uses
 * around kvm_handle_debug(). This also matters for correctness beyond
 * just this call: it serializes this function against vmi_try_arm()
 * (which runs on a *different* OS thread -- the main/iothread -- while
 * this runs on the vCPU's own thread), so the two can never race each
 * other's kvm_insert_breakpoint()/kvm_remove_breakpoint() calls.
 */
void vmi_monitor_kernel_loaded(CPUState *cs)
{
    bool was_locked;

    if (!vmi_enabled || vmi_boot_sync_ok || vmi_first_hit_seen) {
        return;
    }

    vmi_debug("[boot-sync] FW_CFG_KERNEL_DATA transfer completed");

    was_locked = qemu_mutex_iothread_locked();
    vmi_debug("[boot-sync] BQL held on entry: %s", was_locked ? "yes" : "no");
    if (!was_locked) {
        qemu_mutex_lock_iothread();
    }

    vmi_debug("[boot-sync] arming breakpoint at 0x%" PRIx64, (uint64_t)vmi_addr);
    if (vmi_arm_once(cs, "boot-sync")) {
        vmi_boot_sync_ok = true;
        vmi_debug("[boot-sync] guest may resume");
        info_report("vmi-monitor: boot-sync armed breakpoint at 0x%" PRIx64
                    " immediately after the fw_cfg kernel-data transfer "
                    "(no polling needed)", (uint64_t)vmi_addr);
        if (vmi_arm_timer) {
            timer_free(vmi_arm_timer);
            vmi_arm_timer = NULL;
        }
    } else {
        vmi_debug("[boot-sync] arm FAILED -- falling back to periodic retry");
        warn_report("vmi-monitor: boot-sync arm failed at the fw_cfg hook "
                     "-- falling back to the periodic retry path");
    }

    if (!was_locked) {
        qemu_mutex_unlock_iothread();
    }
}

static void vmi_vm_state_change(void *opaque, bool running, RunState state)
{
    vmi_debug("[vm_state_change] running=%d state=%d", running, state);
    if (!running || !vmi_enabled) {
        return;
    }
    if (vmi_arm_timer) {
        vmi_debug("[vm_state_change] arm already in flight, ignoring");
        return; /* an arm sequence is already in flight */
    }

    info_report("vmi-monitor: guest running (state=%d), starting breakpoint "
                "arm attempts at 0x%" PRIx64, state, (uint64_t)vmi_addr);
    vmi_arm_attempts = 0;
    vmi_arm_timer = timer_new_ms(QEMU_CLOCK_REALTIME, vmi_try_arm, NULL);
    vmi_try_arm(NULL); /* try immediately; falls back to timer retries */
}

void vmi_monitor_init(void)
{
    const char *addr_str = getenv("VMI_MONITOR_ADDR");
    const char *log_path;

    if (!addr_str) {
        vmi_enabled = false;
        return;
    }

    vmi_addr = (target_ulong)strtoull(addr_str, NULL, 0);
    if (vmi_addr == 0) {
        error_report("vmi-monitor: VMI_MONITOR_ADDR='%s' could not be "
                     "parsed as a non-zero address -- monitor disabled",
                     addr_str);
        return;
    }

    log_path = getenv("VMI_MONITOR_LOG");
    if (!log_path) {
        log_path = "vmi_monitor.jsonl";
    }
    vmi_log_fp = fopen(log_path, "a");
    if (!vmi_log_fp) {
        error_report("vmi-monitor: could not open log file '%s' (%s) -- "
                     "monitor disabled", log_path, strerror(errno));
        return;
    }

    {
        g_autofree char *debug_path = g_strdup_printf("%s.debug.log", log_path);
        vmi_debug_fp = fopen(debug_path, "a");
    }

    vmi_state_table = g_hash_table_new(g_direct_hash, g_direct_equal);
    vmi_enabled = true;

    vmi_debug("[init] addr=0x%" PRIx64 " log=%s", (uint64_t)vmi_addr, log_path);
    info_report("vmi-monitor: enabled, addr=0x%" PRIx64 " log=%s",
                (uint64_t)vmi_addr, log_path);

    qemu_add_vm_change_state_handler(vmi_vm_state_change, NULL);
}

static void vmi_log_syscall(CPUState *cs, CPUX86State *env)
{
    uint64_t rax = env->regs[R_EAX];
    const VmiSyscallInfo *info = vmi_syscall_lookup((int)rax);
    char namebuf[32];
    const char *name;
    int argc;
    uint64_t argv[6];
    struct timeval tv;
    int i;

    if (info) {
        name = info->name;
        argc = info->argc;
    } else {
        snprintf(namebuf, sizeof(namebuf), "syscall_%" PRIu64, rax);
        name = namebuf;
        argc = 6;
    }

    argv[0] = env->regs[R_EDI];
    argv[1] = env->regs[R_ESI];
    argv[2] = env->regs[R_EDX];
    argv[3] = env->regs[10]; /* r10 */
    argv[4] = env->regs[8];  /* r8  */
    argv[5] = env->regs[9];  /* r9  */

    gettimeofday(&tv, NULL);

    fprintf(vmi_log_fp,
            "{\"ts\": %ld.%06ld, \"cpu\": %d, \"rip\": \"0x%" PRIx64
            "\", \"num\": %" PRIu64 ", \"syscall\": \"%s\", \"args\": [",
            (long)tv.tv_sec, (long)tv.tv_usec, cs->cpu_index,
            (uint64_t)env->eip, rax, name);
    for (i = 0; i < argc && i < 6; i++) {
        fprintf(vmi_log_fp, "%s\"0x%" PRIx64 "\"", i ? ", " : "", argv[i]);
    }
    fprintf(vmi_log_fp, "]}\n");
    fflush(vmi_log_fp);
}

void vmi_monitor_breakpoint_hit(X86CPU *cpu)
{
    CPUState *cs = CPU(cpu);
    CPUX86State *env = &cpu->env;
    int err;

    /* Registers are not synced into env[] on every KVM exit -- must pull
     * them explicitly before reading env->regs[]/env->eip. */
    cpu_synchronize_state(cs);

    vmi_debug("[hit] cpu=%d rip=0x%" PRIx64 " rax=%" PRIu64, cs->cpu_index,
              (uint64_t)env->eip, (uint64_t)env->regs[R_EAX]);

    if (!vmi_first_hit_seen) {
        vmi_first_hit_seen = true;
        vmi_debug("[hit] first real hit observed -- breakpoint confirmed "
                  "live, stopping periodic re-verification");
        info_report("vmi-monitor: first real syscall hit observed at 0x%"
                    PRIx64 " -- breakpoint confirmed live", (uint64_t)vmi_addr);
        if (vmi_arm_timer) {
            timer_free(vmi_arm_timer);
            vmi_arm_timer = NULL;
        }
    }

    vmi_log_syscall(cs, env);

    err = kvm_remove_breakpoint(cs, vmi_addr, 1, GDB_BREAKPOINT_SW);
    if (err) {
        error_report("vmi-monitor: cpu %d: failed to remove breakpoint for "
                     "step-over: %d -- leaving state NORMAL, guest will "
                     "trap here again next time (capture may duplicate "
                     "this event, but stays correct; guest is not stuck)",
                     cs->cpu_index, err);
        return;
    }

    cpu_single_step(cs, 1);
    vmi_monitor_set_state(cs, VMI_STEPPING);
}

void vmi_monitor_step_complete(CPUState *cs)
{
    uint8_t readback = 0;
    bool verified;
    int err;

    cpu_single_step(cs, 0);

    err = kvm_insert_breakpoint(cs, vmi_addr, 1, GDB_BREAKPOINT_SW);
    if (err) {
        error_report("vmi-monitor: cpu %d: failed to reinsert breakpoint "
                     "after step-over: %d -- syscall capture STOPPED for "
                     "this vCPU (guest continues to run normally, "
                     "unmonitored)", cs->cpu_index, err);
        vmi_monitor_set_state(cs, VMI_NORMAL);
        return;
    }

    verified = cpu_memory_rw_debug(cs, vmi_addr, &readback, 1, 0) == 0 &&
               readback == 0xcc;
    if (!verified) {
        error_report("vmi-monitor: cpu %d: reinsert reported success but "
                     "memory readback shows 0x%02x, not 0xcc -- syscall "
                     "capture STOPPED for this vCPU (guest continues to "
                     "run normally, unmonitored)", cs->cpu_index, readback);
        vmi_monitor_set_state(cs, VMI_NORMAL);
        return;
    }

    vmi_monitor_set_state(cs, VMI_NORMAL);
}
