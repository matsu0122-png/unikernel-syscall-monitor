#!/usr/bin/env python3
"""Agentless selective syscall trapping (Phase 11 prototype).

    collector/.venv/bin/python agentless/vmi_trap.py --instance <kraft name> \\
        --group NETFD --jsonl logs/agentless.jsonl [--otel otlp|file|none]

Nothing runs in the guest and QEMU is the unmodified distro binary:

1. HMP `gdbserver` on the instance's monitor socket starts QEMU's gdbstub
   (loopback only); this tool speaks RSP to it (agentless/rsp.py).
2. Before arming, the live dispatcher code, its jump table and the caller
   are compared with the image (agentless/traps.json + the .dbg); any
   difference -> refuse.
3. A software breakpoint (0xCC, QEMU Z0) goes on the tail jump of each
   selected syscall's case block, and only there: unselected syscalls run
   without a VM exit.
4. On a hit the guest is stopped. The tool reads r12 (pointer to the saved
   Linux-ABI registers) and the nr/arguments from guest RAM, then resumes
   at the jump target itself (P rip=target), so it never single-steps an
   instruction the guest chose (Phase 11 check: MOV DR escapes host
   single-step) and the 0xCC is never lifted.
5. With return values (default), a temporary breakpoint on the common exit
   site (after `call uk_syscall6_do_e`) is armed while a selected syscall
   is in flight; the record is matched by stack pointer (rsp at entry + 8).
6. A separate thread re-reads the dispatcher, jump table and caller over
   HMP `xp` every --check-interval-s (the guest keeps running) and reports
   any byte that differs from the image with the armed 0xCCs overlaid. A
   removed trap is re-armed (guest interrupted, z0 + Z0).
7. Records -> JSONL (Phase 2-8 / collector format, host timestamps) and
   OTel spans through collector/traces.py (one trace per connection).

Baked images (agentless/bake_traps.py, Phase 11-2): --traps is the image's
.traps.json. The selection comes from it (--group/--syscalls refused); the
0xCCs are already in guest RAM, so step 3 only registers those addresses
with the gdbstub, and step 2/6 expect 0xCC there. agentless/qemu-trap.sh runs
this with --mon and --ready-file while QEMU is still paused (-S), so every
baked site is registered before the guest's first instruction.

Times are host CLOCK_REALTIME when the stop reaches this tool, so no
guest-host offset is involved; dur_us includes the trap cost.
"""

import argparse
import errno as errno_mod
import json
import os
import signal
import socket
import struct
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "collector"))
sys.path.insert(0, str(ROOT / "legacy"))

from attach_gdbstub import (_recv_until_prompt, attach_gdbserver,  # noqa: E402
                            find_free_port, find_instance_runtime_dir, hmp_command)
from gen_traps import Elf, select  # noqa: E402
from rsp import R12, RAX, RIP, RSP, Rsp, stop_signal  # noqa: E402
from syscall_table import SYSCALL_TABLE  # noqa: E402

F_ENTRY_ONLY = 1
SIGINT_, SIGTRAP_ = 2, 5


def log(msg):
    print(f"[vmi_trap] {msg}", file=sys.stderr, flush=True)


def signed64(v):
    return v - (1 << 64) if v >= 1 << 63 else v


class Rec:
    """Shape collector/traces.py expects."""
    __slots__ = ("nr", "args", "ret", "flags", "tid", "lcpu", "idx",
                 "unselected", "t_enter", "t_exit")

    def __init__(self, nr, args, tid, idx, t_enter):
        self.nr, self.args, self.tid, self.idx = nr, args, tid, idx
        self.t_enter, self.t_exit = t_enter, None
        self.ret, self.flags, self.lcpu, self.unselected = None, F_ENTRY_ONLY, 0, False


# ---------------------------------------------------------------- HMP checks
class Hmp:
    def __init__(self, path):
        self.sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.sock.connect(str(path))
        _recv_until_prompt(self.sock)

    def xp(self, addr, n):
        """Guest-physical bytes (identity-mapped in this image) while it runs."""
        out = bytearray()
        txt = hmp_command(self.sock, f"xp /{n}bx {addr:#x}")
        for line in txt.splitlines():
            _, _, vals = line.partition(":")
            out.extend(int(v, 16) for v in vals.split())
        if len(out) != n:
            raise RuntimeError(f"xp {addr:#x}/{n}: got {len(out)} bytes: {txt[:200]!r}")
        return bytes(out)


class Integrity(threading.Thread):
    def __init__(self, hmp, regions, armed, volatile, interval, alert, repair):
        super().__init__(daemon=True, name="integrity")
        self.hmp, self.regions, self.armed = hmp, regions, armed
        self.volatile, self.interval = volatile, interval
        self.alert, self.repair = alert, repair
        self.stop_ev = threading.Event()
        self.bad = {}          # addr -> live byte currently reported
        self.checks = 0
        self.check_ns = 0

    def expected(self, addr, orig):
        return 0xCC if addr in self.armed else orig

    def check_once(self):
        t0 = time.monotonic_ns()
        now_bad = {}
        for name, base, ref in self.regions:
            live = self.hmp.xp(base, len(ref))
            for i, (got, orig) in enumerate(zip(live, ref)):
                addr = base + i
                if addr in self.volatile:
                    continue
                if got != self.expected(addr, orig):
                    now_bad[addr] = (name, got, orig)
        self.checks += 1
        self.check_ns += time.monotonic_ns() - t0
        for addr, (name, got, orig) in now_bad.items():
            if self.bad.get(addr) != got:
                kind = "trap_removed" if addr in self.armed else "code_modified"
                self.alert(kind, {"region": name, "addr": hex(addr), "live": hex(got),
                                  "expected": hex(self.expected(addr, orig))})
        for addr in set(self.bad) - set(now_bad):
            self.alert("restored", {"addr": hex(addr)})
        self.bad = {a: v[1] for a, v in now_bad.items()}
        removed = [a for a in now_bad if a in self.armed]
        if removed:
            self.repair(removed)

    def run(self):
        while not self.stop_ev.wait(self.interval):
            try:
                self.check_once()
            except Exception as e:      # QEMU gone, socket closed
                log(f"integrity thread stopped: {e}")
                return


# ---------------------------------------------------------------- OTel
def setup_otel(kind, endpoint, dump_path, instance, image_sha, selection):
    if kind == "none":
        return None, None
    from opentelemetry.sdk.resources import Resource
    from opentelemetry.sdk.trace import TracerProvider
    from opentelemetry.sdk.trace.export import BatchSpanProcessor
    res = Resource.create({"service.name": "vmitrace-agentless",
                           "vmitrace.instance": instance,
                           "vmitrace.image_sha256": image_sha,
                           "vmitrace.selection": selection})
    provider = TracerProvider(resource=res)
    if kind == "otlp":
        from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import \
            OTLPSpanExporter
        exporter = OTLPSpanExporter(endpoint=endpoint, insecure=True)
    else:
        from file_exporter import JsonLinesSpanExporter
        exporter = JsonLinesSpanExporter(dump_path)
    provider.add_span_processor(BatchSpanProcessor(exporter, max_queue_size=65536))
    return provider, provider.get_tracer("vmitrace.agentless")


# ---------------------------------------------------------------- test only
TEST_CAVE = 0x140d70      # ramfs_rename (330 bytes): not called while serving GET


def untrap_snippet(site, orig, target):
    """Guest ring-0 code: clear CR0.WP, write `orig` at `site`, restore CR0
    and registers, then go on to `target` with the stack as at the site."""
    return (bytes([0x50, 0x51, 0x52,                    # push rax, rcx, rdx
                   0x0F, 0x20, 0xC0,                    # mov %cr0,%rax
                   0x48, 0x89, 0xC2,                    # mov %rax,%rdx
                   0x48, 0x0F, 0xBA, 0xF0, 0x10,        # btr $16,%rax
                   0x0F, 0x22, 0xC0,                    # mov %rax,%cr0
                   0xC6, 0x04, 0x25]) + struct.pack("<I", site) + bytes([orig])  # movb
            + bytes([0x0F, 0x22, 0xC2,                  # mov %rdx,%cr0
                     0x5A, 0x59, 0x58,                  # pop rdx, rcx, rax
                     0x68]) + struct.pack("<I", target)  # push $target
            + bytes([0xC3]))                            # ret


# ---------------------------------------------------------------- main
def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    tgt = ap.add_mutually_exclusive_group(required=True)
    tgt.add_argument("--instance", help="kraft instance name")
    tgt.add_argument("--mon", help="QEMU HMP monitor socket (used by qemu-trap.sh)")
    ap.add_argument("--traps", default=str(HERE / "traps.json"),
                    help="trap table (gen_traps.py) or a baked image's .traps.json")
    ap.add_argument("--ready-file", help="write this file once every trap is registered")
    ap.add_argument("--resume-by-qemu", action="store_true",
                    help="do not resume the guest after arming; its launcher does "
                         "(QEMU paused with -S, kraftkit's QMP cont)")
    sel = ap.add_mutually_exclusive_group()
    sel.add_argument("--group", help="NET, NETFD (default), FILE, TIME, ALL")
    sel.add_argument("--syscalls", help="comma-separated names, e.g. connect,socket")
    ap.add_argument("--no-ret", action="store_true", help="entry only (no exit trap)")
    ap.add_argument("--jsonl", default=str(ROOT / "logs" / "agentless.jsonl"))
    ap.add_argument("--otel", choices=("otlp", "file", "none"), default="none")
    ap.add_argument("--otlp-endpoint", default="127.0.0.1:14317")
    ap.add_argument("--otel-file")
    ap.add_argument("--check-interval-s", type=float, default=1.0,
                    help="trap/code check over HMP; 0 disables")
    ap.add_argument("--port", type=int)
    ap.add_argument("--stats", help="write final statistics (JSON) here")
    ap.add_argument("--test-guest-untrap", metavar="SYSCALL",
                    help="TEST ONLY: at this syscall's first hit, make the guest itself "
                         "(ring 0, CR0.WP cleared) write the original byte over its 0xCC, "
                         "then continue the syscall; checks detection and re-arming")
    a = ap.parse_args()

    traps = json.loads(Path(a.traps).read_text())
    sites = {int(k): v for k, v in traps["sites"].items()}
    baked = traps.get("baked")
    if baked:
        if a.group or a.syscalls:
            raise SystemExit("baked image: the selection is fixed at build time "
                             f"({baked['selection']}); drop --group/--syscalls")
        nrs = baked["nrs"]
    else:
        nrs = select(traps, a.group, a.syscalls)
    # site -> (nrs that reach it, jump target); a shared case block has several
    entry = {}
    for nr in nrs:
        s = sites[nr]
        entry.setdefault(s["site"], ([], s["target"]))[0].append(nr)
    baked_sites = set(baked["sites"]) if baked else set()
    if baked and baked_sites != set(entry):
        raise SystemExit(f"{a.traps}: baked sites do not match its nrs")
    exit_site = traps["exit_site"]
    want_ret = not a.no_ret
    regs_off = traps["regs_layout"]
    untrap = None
    if a.test_guest_untrap:
        nr_t = next(nr for nr, v in sites.items() if v["name"] == a.test_guest_untrap)
        if nr_t not in nrs:
            raise SystemExit(f"{a.test_guest_untrap} is not selected")
        untrap = (nr_t, untrap_snippet(sites[nr_t]["site"], sites[nr_t]["orig_byte"],
                                       sites[nr_t]["target"]))

    elf = Elf(traps["image_dbg"])
    d, c = traps["dispatcher"], traps["caller"]
    regions = [("dispatcher", d["addr"], elf.read(d["addr"], d["size"])),
               ("jump_table", d["table"], elf.read(d["table"], (d["nr_max"] + 1) * 8)),
               ("caller", c["addr"], elf.read(c["addr"], c["size"]))]

    mon = Path(a.mon) if a.mon else find_instance_runtime_dir(a.instance) / "mon.sock"
    instance = a.instance or mon.parent.name
    port = a.port or find_free_port(1240)
    try:
        attach_gdbserver(mon, port)
    except RuntimeError as e:
        # QEMU keeps the stub listening after a detach; reuse it.
        if not (a.port and "Could not open gdbserver" in str(e)):
            raise
        log(f"gdbstub already listening on {port}, reusing it")
    hmp = Hmp(mon)

    # 2. the running image must be the one the table was made from
    #    (a baked image: with 0xCC on exactly the baked sites)
    for name, base, ref in regions:
        live = hmp.xp(base, len(ref))
        ref = bytes(0xCC if base + i in baked_sites else b for i, b in enumerate(ref))
        if live != ref:
            diff = [hex(base + i) for i, (x, y) in enumerate(zip(live, ref)) if x != y]
            raise SystemExit(f"live {name} differs from {traps['image_dbg']} at "
                             f"{diff[:8]} ({len(diff)} bytes): wrong image or already modified")

    names = {nr: SYSCALL_TABLE.get(nr, (sites[nr]["name"], 6)) for nr in sites}
    out = open(a.jsonl, "a", buffering=1)
    provider, tracer = setup_otel(a.otel, a.otlp_endpoint, a.otel_file, instance,
                                  baked["image_sha256"] if baked
                                  else traps["image_dbg_sha256"],
                                  f"baked:{baked['selection']}" if baked
                                  else a.syscalls or (a.group or "NETFD").upper())
    if tracer is not None:
        log(f"OTel: {a.otel} " + (a.otlp_endpoint if a.otel == "otlp" else str(a.otel_file)))
    tb = None
    if tracer is not None:
        from traces import TraceBuilder
        tb = TraceBuilder(tracer)

    out_lock = threading.Lock()
    stats = {"hits": {}, "entries": 0, "exits": 0, "unmatched_exits": 0,
             "exit_step_overs": 0, "nr_mismatch": 0, "foreign_traps": 0,
             "interrupts": 0, "rearmed": 0, "alerts": {}, "stop_handling_ns": 0,
             "stops": 0}

    def alert(kind, info):
        stats["alerts"][kind] = stats["alerts"].get(kind, 0) + 1
        t = time.time_ns()
        line = {"ts": t / 1e9, "event": kind, **info}
        log(f"ALERT {kind} {info}")
        with out_lock:
            out.write(json.dumps(line) + "\n")
            if tracer is not None:
                sp = tracer.start_span(f"integrity.{kind}", start_time=t,
                                       attributes={f"vmitrace.{k}": str(v)
                                                   for k, v in info.items()})
                sp.end(end_time=t + 1000)    # 0 length: Jaeger adds a warning

    rsp = Rsp("127.0.0.1", port)
    repair_q, repair_lock = set(), threading.Lock()
    stop = threading.Event()

    def request_repair(addrs):
        with repair_lock:
            repair_q.update(addrs)
        rsp.interrupt()

    def on_signal(*_):
        stop.set()
        rsp.interrupt()
    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    reason = rsp.start()
    log(f"attached on port {port} ({reason}); "
        + (f"registering {len(entry)} baked traps ({baked['selection']}): " if baked
           else f"arming {len(entry)} traps: ")
        + ",".join(names[n][0] for n in nrs))
    armed = set()
    for site in entry:
        # baked: the byte is already 0xCC; Z0 makes QEMU/KVM report the hit
        # to us instead of injecting #BP into the guest
        rsp.insert(site)
        armed.add(site)
    if a.ready_file:
        Path(a.ready_file).write_text(f"{port}\n")
    check = None
    if a.check_interval_s > 0:
        check = Integrity(hmp, regions, armed, {exit_site}, a.check_interval_s,
                          alert, request_repair)

    def emit(recs):
        with out_lock:
            for r in recs:
                name, nargs = names[r.nr]
                args_hex = [hex(x) for x in r.args[:nargs]]
                line = {"ts": r.t_enter / 1e9, "cpu": 0, "num": r.nr, "syscall": name,
                        "args": args_hex}
                if r.flags & F_ENTRY_ONLY:
                    line["ret"] = None
                    end = r.t_enter
                else:
                    line["ret"] = r.ret
                    if -4096 < r.ret < 0:
                        line["err"] = errno_mod.errorcode.get(-r.ret, str(-r.ret))
                    line["dur_us"] = (r.t_exit - r.t_enter) // 1000
                    end = r.t_exit
                line["tid"] = r.tid
                line["idx"] = r.idx
                line["src"] = "trap"
                out.write(json.dumps(line) + "\n")
                if tb is not None:
                    tb.add(r, name, r.t_enter, end, args_hex)

    pending = {}            # rsp at entry -> Rec
    exit_armed = False
    seq = 0
    guest_gone = False
    if check is not None:
        check.start()
    # With --resume-by-qemu, kraftkit's QMP `cont` resumes the guest; the
    # stub (QEMU 6.2) still reports each later stop to this client.
    if not a.resume_by_qemu:
        rsp.cont()
    t_start = time.time()
    try:
        while True:
            reply = rsp.wait_stop()
            t = time.time_ns()
            t0 = time.monotonic_ns()
            sig = stop_signal(reply)
            if sig is None:
                log(f"guest exited: {reply}")
                guest_gone = True
                break
            stats["stops"] += 1
            done = []
            if stop.is_set():
                break
            with repair_lock:
                todo = list(repair_q)
                repair_q.clear()
            for site in todo:               # re-arm a trap the guest removed
                rsp.remove(site)
                rsp.insert(site)
                stats["rearmed"] += 1
                alert("trap_rearmed", {"addr": hex(site),
                                       "live_after": hex(rsp.read(site, 1)[0])})
            if sig == SIGTRAP_:
                regs = rsp.regs()
                pc = regs[RIP]
                if pc in entry:
                    site_nrs, target = entry[pc]
                    base = regs[R12]
                    raw = rsp.read(base + 0x40, 0x48)
                    v = lambda off: struct.unpack_from("<Q", raw, off - 0x40)[0]  # noqa: E731
                    nr_saved = v(regs_off["orig_rax"])
                    nr = nr_saved if nr_saved in site_nrs else site_nrs[0]
                    if nr_saved not in site_nrs:
                        stats["nr_mismatch"] += 1
                        alert("nr_mismatch", {"site": hex(pc), "site_nrs": site_nrs,
                                              "orig_rax": nr_saved})
                    args = [v(regs_off[r]) for r in ("rdi", "rsi", "rdx", "r10", "r8", "r9")]
                    rec = Rec(nr, args, base, seq, t)
                    seq += 1
                    stats["entries"] += 1
                    stats["hits"][nr] = stats["hits"].get(nr, 0) + 1
                    if want_ret:
                        pending[regs[RSP]] = rec
                        if not exit_armed:
                            rsp.insert(exit_site)
                            exit_armed = True
                    else:
                        done.append(rec)
                    if untrap is not None and untrap[0] == nr:
                        rsp.write(TEST_CAVE, untrap[1])
                        rsp.set_reg(RIP, TEST_CAVE)
                        log(f"TEST: guest code at {TEST_CAVE:#x} removes the trap at {pc:#x}")
                        untrap = None
                    else:
                        rsp.set_reg(RIP, target)
                elif pc == exit_site and exit_armed:
                    rec = pending.pop(regs[RSP] - 8, None)
                    if rec is None:
                        stats["unmatched_exits"] += 1
                    else:
                        rec.ret = signed64(regs[RAX])
                        rec.flags = 0
                        rec.t_exit = t
                        stats["exits"] += 1
                        done.append(rec)
                    rsp.remove(exit_site)
                    if pending:             # another thread still inside one
                        rsp.step()
                        rsp.insert(exit_site)
                        stats["exit_step_overs"] += 1
                    else:
                        exit_armed = False
                else:
                    stats["foreign_traps"] += 1
                    alert("foreign_trap", {"pc": hex(pc)})
                    if stats["foreign_traps"] > 20:
                        raise SystemExit("repeated traps not set by this tool; stopping")
            else:
                stats["interrupts"] += 1
            rsp.cont()
            stats["stop_handling_ns"] += time.monotonic_ns() - t0
            if done:
                emit(done)
    except EOFError as e:
        log(str(e))
    finally:
        if check is not None:
            check.stop_ev.set()
        try:
            if not rsp.sock._closed and not guest_gone:
                for site in list(armed) + ([exit_site] if exit_armed else []):
                    rsp.remove(site)
                rsp.detach()
                log("traps removed, detached"
                    + ("; the baked 0xCCs stay in the guest: its next selected "
                       "syscall crashes it" if baked else ""))
        except Exception as e:
            log(f"cleanup: {e}")
        for r in pending.values():
            emit([r])
        if tb is not None:
            tb.flush()
        if provider is not None:
            provider.shutdown()
        out.close()
        stats["wall_s"] = round(time.time() - t_start, 3)
        stats["round_trips"] = rsp.round_trips
        stats["hits"] = {names[k][0]: v for k, v in sorted(stats["hits"].items())}
        if stats["stops"]:
            stats["mean_stop_handling_us"] = round(stats["stop_handling_ns"] / stats["stops"] / 1000, 1)
        if check is not None:
            stats["integrity_checks"] = check.checks
            if check.checks:
                stats["mean_check_ms"] = round(check.check_ns / check.checks / 1e6, 2)
        if tb is not None:
            stats["traces"] = tb.stats
        txt = json.dumps(stats, indent=1)
        log("stats " + txt)
        if a.stats:
            Path(a.stats).write_text(txt + "\n")


if __name__ == "__main__":
    main()
