#!/usr/bin/env python3
"""Build the trap table for agentless selective trapping (Phase 11).

    python3 agentless/gen_traps.py <image>.dbg -o agentless/traps.json

Reads the unmodified image; nothing is added to the guest.

Binary syscalls reach one dispatcher, uk_syscall6_do_e(regs):

    cmpq $MAX, 0x80(%rdi)          # regs->orig_rax
    ja   <default: -ENOSYS>
    mov  0x80(%rdi), %rax
    jmp  *TABLE(,%rax,8)           # one case block per syscall number
  case_N:
    mov  ..(%rdi), <arg regs>      # SysV arguments from the saved regs
    jmp  uk_syscall_do_<name>      # tail call  <- trap site for nr N

The only caller is ukplat_syscall_handler (`mov %r12,%rdi; call
uk_syscall6_do_e`), so at a trap site r12 still points at the saved
Linux-ABI registers, and every handler returns to the instruction after
that call (the exit site).

This script reads the jump table out of the ELF, follows each case block
to its tail jump, and records per syscall number: site address, the
original opcode byte (what the guest must hold when no trap is set), and
the jump target (the host resumes there instead of single-stepping).
It refuses to write a table when the code does not have this shape.
"""

import argparse
import hashlib
import json
import re
import struct
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent))
from syscall_table import SYSCALL_TABLE  # noqa: E402

GROUPS_H = HERE.parent / "guest" / "lib-vmitrace" / "groups.h"
DISPATCHER = "uk_syscall6_do_e"
CALLER = "ukplat_syscall_handler"
INSN_RE = re.compile(r"^\s*([0-9a-f]+):\s+(.*?)\s*$")


class Elf:
    """Just enough ELF64 to map a virtual address to file bytes."""

    def __init__(self, path):
        self.data = Path(path).read_bytes()
        d = self.data
        if d[:4] != b"\x7fELF" or d[4] not in (1, 2):
            raise SystemExit(f"{path}: not ELF")
        # The .dbg is ELF64; the bootable multiboot image is ELF32 with the
        # same virtual addresses.
        if d[4] == 2:
            shoff, = struct.unpack_from("<Q", d, 0x28)
            shentsize, shnum = struct.unpack_from("<HH", d, 0x3A)
            sh_fmt = "<IIQQQQIIQQ"
        else:
            shoff, = struct.unpack_from("<I", d, 0x20)
            shentsize, shnum = struct.unpack_from("<HH", d, 0x2E)
            sh_fmt = "<IIIIIIIIII"
        self.entry, = struct.unpack_from("<Q" if d[4] == 2 else "<I", d, 0x18)
        self.sections = []
        for i in range(shnum):
            (_, sh_type, _, addr, off, size, *_rest) = struct.unpack_from(
                sh_fmt, d, shoff + i * shentsize)
            if addr and sh_type != 8:          # skip SHT_NOBITS
                self.sections.append((addr, off, size))

    def offset(self, vaddr, n=1):
        """File offset of vaddr (n bytes must lie in one section)."""
        for addr, off, size in self.sections:
            if addr <= vaddr and vaddr + n <= addr + size:
                return off + vaddr - addr
        raise KeyError(hex(vaddr))

    def read(self, vaddr, n):
        off = self.offset(vaddr, n)
        return self.data[off:off + n]


def symbols(path):
    out = subprocess.run(["nm", "-S", path], capture_output=True, text=True,
                         check=True).stdout
    syms = {}
    for line in out.splitlines():
        p = line.split()
        if len(p) == 4:
            syms[p[3]] = (int(p[0], 16), int(p[1], 16))
    return syms


def disasm(path, start, size):
    out = subprocess.run(
        ["objdump", "-d", "--no-show-raw-insn", f"--start-address={start:#x}",
         f"--stop-address={start + size:#x}", path],
        capture_output=True, text=True, check=True).stdout
    insns = []
    for line in out.splitlines():
        m = INSN_RE.match(line)
        if m and not line.rstrip().endswith(">:"):
            insns.append((int(m.group(1), 16), m.group(2)))
    return insns


def parse_groups():
    text = GROUPS_H.read_text()
    groups = {}
    for name, body in re.findall(
            r"#define VMITRACE_GROUP_(\w+)\(X, a\)(.*?)(?:\n\n|\n#)", text, re.S):
        groups[name] = re.findall(r"X\((\w+), a\)", body)
    groups["NETFD"] = groups["NET"] + groups.pop("NETFD_EXTRA")
    return groups


def build_table(dbg):
    """Trap table (dict) for the image whose .dbg is `dbg`; SystemExit when
    the dispatcher does not have the expected shape."""
    syms = symbols(dbg)
    elf = Elf(dbg)
    d_addr, d_size = syms[DISPATCHER]
    insns = disasm(dbg, d_addr, d_size)
    by_addr = {addr: i for i, (addr, _) in enumerate(insns)}

    # Prologue: cmpq $MAX,0x80(%rdi); ja DEFAULT; mov 0x80(%rdi),%rax; jmp *TABLE(,%rax,8)
    m_cmp = re.fullmatch(r"cmpq\s+\$0x([0-9a-f]+),0x80\(%rdi\)", insns[0][1])
    m_ja = re.fullmatch(r"ja\s+([0-9a-f]+) .*", insns[1][1])
    m_jt = re.fullmatch(r"jmp\s+\*0x([0-9a-f]+)\(,%rax,8\)", insns[3][1])
    if not (m_cmp and m_ja and m_jt
            and re.fullmatch(r"mov\s+0x80\(%rdi\),%rax", insns[2][1])):
        raise SystemExit(f"{DISPATCHER}: unexpected prologue:\n" +
                         "\n".join(f"  {x:#x}: {s}" for x, s in insns[:4]))
    nr_max = int(m_cmp.group(1), 16)
    default = int(m_ja.group(1), 16)
    table = int(m_jt.group(1), 16)

    # r12 must survive into every case block (it is the regs pointer at the site).
    clobber = [f"{x:#x}: {s}" for x, s in insns if re.search(r",%r12d?$", s)]
    if clobber:
        raise SystemExit(f"{DISPATCHER} writes r12: {clobber}")

    c_addr, c_size = syms[CALLER]
    cins = disasm(dbg, c_addr, c_size)
    calls = [i for i, (_, s) in enumerate(cins)
             if re.fullmatch(rf"call\s+{d_addr:x} <{DISPATCHER}>", s)]
    if len(calls) != 1 or not any(re.fullmatch(r"mov\s+%r12,%rdi", s)
                                  for _, s in cins[calls[0] - 3:calls[0]]):
        raise SystemExit(f"{CALLER}: expected one `mov %r12,%rdi ... call {DISPATCHER}`")
    exit_site = cins[calls[0] + 1][0]

    sites, unsupported, problems = {}, [], []
    for nr in range(nr_max + 1):
        case = struct.unpack("<Q", elf.read(table + 8 * nr, 8))[0]
        if case == default:
            unsupported.append(nr)
            continue
        if case not in by_addr:
            problems.append(f"nr {nr}: case {case:#x} is not an instruction start")
            continue
        i = by_addr[case]
        while i < len(insns):
            addr, s = insns[i]
            m = re.fullmatch(r"jmp\s+([0-9a-f]+) <uk_syscall_do_(\w+)>", s)
            if m:
                break
            if not re.match(r"(mov|movslq|movl|xor|lea)\s", s):
                problems.append(f"nr {nr}: case block has `{s}` at {addr:#x} before its tail jump")
                m = None
                break
            i += 1
        if not m:
            continue
        handler = m.group(2)
        execenv = handler.startswith("e_")      # uk_syscall_do_e_*: takes the execenv
        if execenv:
            handler = handler[2:]
        name = SYSCALL_TABLE.get(nr, (handler, 6))[0]
        if name != handler:
            problems.append(f"nr {nr}: table name {name!r} but handler uk_syscall_do_{handler}")
        op = elf.read(addr, 1)[0]
        if op != 0xE9:
            problems.append(f"nr {nr}: site {addr:#x} opcode {op:#x}, expected 0xe9 (jmp rel32)")
        sites[nr] = {"name": handler, "site": addr, "orig_byte": op,
                     "target": int(m.group(1), 16), "case": case,
                     "execenv": execenv}

    if problems:
        raise SystemExit("refusing to write a trap table:\n  " + "\n  ".join(problems))

    shared = {}
    for nr, s in sites.items():
        shared.setdefault(s["site"], []).append(nr)
    shared = {f"{k:#x}": v for k, v in shared.items() if len(v) > 1}

    by_name = {s["name"]: nr for nr, s in sites.items()}
    groups = {}
    for g, names in parse_groups().items():
        groups[g] = sorted(by_name[n] for n in names if n in by_name)
    groups["ALL"] = sorted(sites)

    return {
        "image_dbg": str(Path(dbg).resolve()),
        "image_dbg_sha256": hashlib.sha256(elf.data).hexdigest(),
        "dispatcher": {"addr": d_addr, "size": d_size, "nr_max": nr_max,
                       "table": table, "default": default},
        "caller": {"addr": c_addr, "size": c_size},
        "regs_ptr_reg": "r12",
        "regs_layout": {"orig_rax": 0x80, "rdi": 0x78, "rsi": 0x70, "rdx": 0x68,
                        "r10": 0x40, "r8": 0x50, "r9": 0x48, "rax": 0x58},
        "exit_site": exit_site,
        "exit_site_orig_byte": elf.read(exit_site, 1)[0],
        "sites": {str(nr): s for nr, s in sorted(sites.items())},
        "shared_sites": shared,
        "unsupported_nrs": unsupported,
        "groups": groups,
    }


def select(table, group=None, syscalls=None):
    """Syscall numbers for a group name or comma-separated syscall names."""
    sites = table["sites"]
    if syscalls:
        by_name = {v["name"]: int(nr) for nr, v in sites.items()}
        names = [n for n in syscalls.split(",") if n]
        missing = [n for n in names if n not in by_name]
        if missing:
            raise SystemExit(f"not dispatched in this image: {missing}")
        return sorted(by_name[n] for n in names)
    key = (group or "NETFD").upper()
    if key not in table["groups"]:
        raise SystemExit(f"unknown group {group!r}; have {sorted(table['groups'])}")
    return list(table["groups"][key])


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("dbg", help="the image's .dbg ELF (symbols; same .text as the image)")
    ap.add_argument("-o", "--out", default=str(HERE / "traps.json"))
    a = ap.parse_args()

    out = build_table(a.dbg)
    Path(a.out).write_text(json.dumps(out, indent=1) + "\n")
    print(f"{len(out['sites'])} trap sites, {len(out['unsupported_nrs'])} unsupported nrs, "
          f"exit site {out['exit_site']:#x}, shared sites {len(out['shared_sites'])} -> {a.out}")
    for g, nrs in out["groups"].items():
        print(f"  {g}: {len(nrs)}")


if __name__ == "__main__":
    main()
