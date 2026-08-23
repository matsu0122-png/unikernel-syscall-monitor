"""gdb-Python capture script -- runs INSIDE gdb's embedded interpreter.

Usage (see run_capture.py for the orchestrated version):
    gdb -q -nx \
        -ex "file .../nginx_qemu-x86_64.dbg" \
        -ex "target remote localhost:<PORT>" \
        -x monitor.py \
        -ex "continue"

Note: this script only sets the breakpoint -- it does NOT itself call
`gdb.execute("continue")`. That's deliberate: `_resolve_hook_address()`
only needs the symbol table (from `file`), not a live target, so this
script can also be `source`d *before* `target remote` connects (the
breakpoint becomes pending and activates once a target attaches) --
see run_capture_from_boot.py, which relies on this to pre-load symbols
and pre-arm the breakpoint while the guest is still paused at boot,
instead of after. Callers must issue `continue` themselves once a
target is actually attached.

Environment variables (all optional):
    VMI_LOG_PATH      output JSONL path (default: logs/capture.jsonl)
    VMI_INCLUDE_NRS   comma-separated syscall numbers to capture; if set,
                      all others are ignored (default: capture everything)
    VMI_EXCLUDE_NRS   comma-separated syscall numbers to skip (default: none)
    VMI_MAX_EVENTS    stop capturing (detach) after N events (default: unlimited)

Design notes (see /home/matsu/.claude/plans/moonlit-kindling-dragon.md):
- Breakpoint is a plain software `break` (gdb.Breakpoint default), NOT
  hbreak -- KVM's hardware-breakpoint path (KVM_SET_GUEST_DEBUG) has
  known upstream reliability bugs. Do not change this to hbreak.
- stop() returns False, which tells gdb NOT to actually stop the
  inferior -- i.e. auto-continue. This is the opposite of naive
  intuition (False sounds like "don't run"), so it is called out here
  and at the return site: DO NOT change this to `return True`, that
  would freeze the guest on every single syscall.
- The hook address (_ukplat_syscall) is resolved by symbol lookup, not
  hardcoded, so this survives a rebuild even if LTO/linking shifts the
  address (confirmed stable at 0x101000 for the current build, but that
  is not guaranteed for future builds).
"""
import gdb  # type: ignore
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from syscall_table import SYSCALL_TABLE  # noqa: E402

LOG_PATH = os.environ.get(
    "VMI_LOG_PATH",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "logs", "capture.jsonl"),
)


def _parse_nr_set(env_var: str):
    raw = os.environ.get(env_var, "")
    if not raw.strip():
        return None
    return {int(x) for x in raw.split(",") if x.strip()}


INCLUDE_NRS = _parse_nr_set("VMI_INCLUDE_NRS")
EXCLUDE_NRS = _parse_nr_set("VMI_EXCLUDE_NRS") or set()
MAX_EVENTS = int(os.environ["VMI_MAX_EVENTS"]) if os.environ.get("VMI_MAX_EVENTS") else None


class SyscallBreakpoint(gdb.Breakpoint):
    def __init__(self, location):
        super().__init__(location, internal=False)
        os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
        self._log = open(LOG_PATH, "a", buffering=1)  # line-buffered
        self.event_count = 0
        print(f"[monitor.py] logging to {LOG_PATH}", flush=True)

    def stop(self):
        t_enter = time.perf_counter()
        frame = gdb.selected_frame()
        rax = int(frame.read_register("rax"))
        # Filter on the raw number before doing anything else with it.
        if (INCLUDE_NRS is not None and rax not in INCLUDE_NRS) or rax in EXCLUDE_NRS:
            return False

        name, argc = SYSCALL_TABLE.get(rax, (f"syscall_{rax}", 6))
        arg_regs = ["rdi", "rsi", "rdx", "r10", "r8", "r9"]
        args = [int(frame.read_register(r)) for r in arg_regs[:argc]]

        event = {
            "ts": time.time(),
            "num": rax,
            "syscall": name,
            "args": [hex(a) for a in args],
        }
        t_exit = time.perf_counter()
        event["handler_latency_ns"] = round((t_exit - t_enter) * 1e9)

        event_line = json.dumps(event)
        self._log.write(event_line + "\n")
        print(f"[monitor.py] {event_line}", flush=True)
        self.event_count += 1

        if MAX_EVENTS is not None and self.event_count >= MAX_EVENTS:
            print(f"[monitor.py] reached VMI_MAX_EVENTS={MAX_EVENTS}, detaching", flush=True)
            self._log.close()
            gdb.execute("detach")
            gdb.execute("quit")

        # IMPORTANT: False means "do not stop the inferior" (auto-continue).
        # Returning True here would freeze the guest on every syscall.
        return False


def _resolve_hook_address():
    # _ukplat_syscall is an assembly-only label (plat/common/x86/syscall.S),
    # so it has no DWARF debug_info entry -- gdb's Python symbol-lookup API
    # (lookup_global_symbol) searches DWARF only and won't find it. But
    # gdb's own breakpoint-location parser (what "break *_ukplat_syscall"
    # does at the CLI) resolves plain ELF/minimal symbols too -- confirmed
    # working manually in Phase 1. So just use that spec directly; only
    # fall back to the hardcoded address if gdb can't resolve it at all
    # (e.g. a rebuild renamed/inlined it).
    FALLBACK_ADDR = 0x101000
    try:
        gdb.decode_line("*_ukplat_syscall")
        return "*_ukplat_syscall"
    except gdb.error as e:
        print(
            f"[monitor.py] WARNING: could not resolve _ukplat_syscall symbol "
            f"({e}), falling back to hardcoded address {FALLBACK_ADDR:#x}. "
            f"This address is only valid for the exact build this was "
            f"checked against -- verify it before trusting captured data."
        )
        return f"*{FALLBACK_ADDR:#x}"


_bp = SyscallBreakpoint(_resolve_hook_address())
print("[monitor.py] breakpoint armed, auto-continuing on every hit", flush=True)
# NOTE: no gdb.execute("continue") here -- see module docstring. The
# caller (gdb_session.py's -ex "continue", or run_capture_from_boot.py's
# interactive "continue") is responsible for starting/resuming the target.
