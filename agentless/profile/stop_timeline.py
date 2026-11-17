#!/usr/bin/env python3
"""Split QEMU's side of each trap stop into segments, from a trace log.

    python3 agentless/profile/stop_timeline.py qemu-trace.log

The log comes from QEMU started with `-msg timestamp=on -d trace:runstate_set
-D FILE` and, over HMP, `trace-event` on for kvm_run_exit, kvm_vcpu_ioctl,
gdbstub_io_command and gdbstub_io_reply (kvm_vm_ioctl, vm_state_notify
optional). Lines: `<tid>@<sec>.<usec>:<event> <args>`.

Per stop (KVM_EXIT_DEBUG = kvm_run_exit reason 4):
  stop_path     exit -> stop reply (T05) sent           QEMU: vCPU -> main loop,
                                                         runstate debug, notifiers
  client_*      reply sent -> next command received     client turnaround + loopback
  qemu_<cmd>    command received -> its reply sent      QEMU work for the command
  resume_path   `c` received -> next KVM_RUN            notifiers, vCPU wakeup,
                                                         registers written back
and the KVM ioctls issued in stop_path, during `g`, and in resume_path.
"""
import re
import statistics
import sys
from collections import Counter, defaultdict

LINE = re.compile(r"^(\d+)@(\d+)\.(\d+):(\S+) ?(.*)$")
KVM_RUN = "0xae80"
NAMES = {
    "0xae80": "RUN", "0x8090ae81": "GET_REGS", "0x4090ae82": "SET_REGS",
    "0x8138ae83": "GET_SREGS", "0x4138ae84": "SET_SREGS", "0xc008ae88": "GET_MSRS",
    "0x4008ae89": "SET_MSRS", "0x8400ae8e": "GET_LAPIC", "0x4400ae8f": "SET_LAPIC",
    "0x8004ae98": "GET_MP_STATE", "0x4004ae99": "SET_MP_STATE",
    "0x8040ae9f": "GET_VCPU_EVENTS", "0x4040aea0": "SET_VCPU_EVENTS",
    "0x8080aea1": "GET_DEBUGREGS", "0x4080aea2": "SET_DEBUGREGS",
    "0x9000aea4": "GET_XSAVE", "0x5000aea5": "SET_XSAVE", "0x8188aea6": "GET_XCRS",
    "0x4188aea7": "SET_XCRS", "0xaead": "KVMCLOCK_CTRL", "0xc080aebe": "GET_NESTED_STATE",
    "0x4048ae9b": "SET_GUEST_DEBUG",
    # vm ioctls
    "vm:0x4030ae7b": "SET_CLOCK", "vm:0x8030ae7c": "GET_CLOCK", "vm:0x4040ae79": "IOEVENTFD",
    "vm:0x8070ae9f": "GET_PIT2", "vm:0x4070aea0": "SET_PIT2", "vm:0xc008ae67": "IRQ_LINE_STATUS",
}


def parse(path):
    ev = []
    for ln in open(path, errors="replace"):
        m = LINE.match(ln)
        if not m:
            continue
        tid, s, us, name, args = m.groups()
        t = int(s) * 1_000_000 + int(us)
        if name == "kvm_vcpu_ioctl":
            ty = re.search(r"type (0x[0-9a-f]+)", args).group(1)
            ev.append((t, tid, "ioctl", NAMES.get(ty, ty)))
        elif name == "kvm_vm_ioctl":
            ty = re.search(r"type (0x[0-9a-f]+)", args).group(1)
            ev.append((t, tid, "ioctl", NAMES.get("vm:" + ty, "vm:" + ty)))
        elif name == "kvm_run_exit":
            ev.append((t, tid, "exit", args.split("reason ")[1].strip()))
        elif name == "gdbstub_io_command":
            ev.append((t, tid, "cmd", args.split("Received: ", 1)[1][:3]))
        elif name == "gdbstub_io_reply":
            ev.append((t, tid, "reply", args.split("Sent: ", 1)[1][:3]))
        elif name == "runstate_set":
            ev.append((t, tid, "runstate", args.split("new_state ")[1]))
    return ev


def main():
    ev = parse(sys.argv[1])
    seg = defaultdict(list)
    ioc = {"stop_path": Counter(), "qemu_g": Counter(), "resume_path": Counter()}
    nstops = 0
    i = 0
    n = len(ev)
    while i < n:
        t, tid, kind, val = ev[i]
        if not (kind == "exit" and val == "4"):
            i += 1
            continue
        # one stop: from this debug exit to the next KVM_RUN after `c`
        t_exit, j = t, i + 1
        phase, last_t, last_cmd, ok = "stop_path", t_exit, None, False
        cur = Counter()
        segs = {}
        while j < n:
            t2, _, k2, v2 = ev[j]
            if k2 == "ioctl" and v2 != "RUN" and phase in ioc:
                cur[v2] += 1
            if k2 == "reply" and v2.startswith("T05") and phase == "stop_path":
                segs["stop_path"] = t2 - last_t
                ioc["stop_path"].update(cur)
                cur = Counter()
                phase, last_t = "client", t2
            elif k2 == "cmd" and phase == "client":
                c = v2[0] if v2[0] not in "Zz" else v2[:2]
                segs[f"client_before_{c}"] = t2 - last_t
                last_t, last_cmd = t2, c
                if c == "c":
                    phase = "resume_path"
                    cur = Counter()
                else:
                    phase = f"qemu_{c}"
                    cur = Counter()
            elif k2 == "reply" and phase.startswith("qemu_"):
                segs[phase] = t2 - last_t
                if phase == "qemu_g":
                    ioc["qemu_g"].update(cur)
                phase, last_t = "client", t2
            elif k2 == "ioctl" and v2 == "RUN" and phase == "resume_path":
                segs["resume_path"] = t2 - last_t
                ioc["resume_path"].update(cur)
                segs["total_exit_to_run"] = t2 - t_exit
                ok = True
                break
            elif k2 == "exit" and v2 == "4":
                break
            j += 1
        if ok:
            nstops += 1
            for k, v in segs.items():
                seg[k].append(v)
        i = j if j > i else i + 1

    print(f"stops: {nstops}")
    order = ["stop_path", "client_before_g", "qemu_g", "client_before_m", "qemu_m",
             "client_before_Z0", "qemu_Z0", "client_before_P", "qemu_P", "client_before_z0",
             "qemu_z0", "client_before_c", "resume_path", "total_exit_to_run"]
    print(f"{'segment':22s} {'n':>5s} {'median us':>9s} {'mean us':>8s} {'p90 us':>7s}")
    for k in order + sorted(set(seg) - set(order)):
        if k in seg:
            v = sorted(seg[k])
            print(f"{k:22s} {len(v):5d} {statistics.median(v):9.0f} "
                  f"{statistics.mean(v):8.1f} {v[len(v) * 9 // 10]:7.0f}")
    for k, c in ioc.items():
        if nstops:
            print(f"ioctls per stop in {k}: " + ", ".join(
                f"{name} {cnt / nstops:.1f}" for name, cnt in c.most_common()))


if __name__ == "__main__":
    main()
