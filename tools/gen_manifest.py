#!/usr/bin/env python3
"""Write manifest.json for a lib-vmitrace build (Phase 10-2).

The manifest is what the host side trusts; the guest's own header is only
checked against it. Everything is taken from the build output, never from a
running guest:

  build_id        sha256 of the image QEMU boots (Unikraft's linker script
                  discards .note.gnu.build-id, so there is no GNU build-id)
  abi             header constants (magic, version, record_size, ...)
  expected        state_addr / records_addr / bitmap_addr as the header must
                  hold them, cross-checked against the ELF symbols
  ring            NOBITS storage: state array, records, sizes
  bitmap          address, sha256, selected syscalls, Kconfig groups
  hash_regions    byte ranges that must be identical in guest RAM: header,
                  bitmap, .vmitrace_text, both hook tables, and the functions
                  the hooks run through (ukplat_syscall_handler,
                  ukplat_monotonic_clock, uk_sys_gettid)
  excluded        boot page tables inside .text (x86_bpt_*, rewritten at
                  boot); no hash region may overlap them

Addresses are guest physical = file offset in the memory-backend-file
(Phase 10-0 §5).

    python3 tools/gen_manifest.py <build>/nginx_qemu-x86_64.dbg [-o manifest.json]
    python3 tools/gen_manifest.py <dbg> --check-mem /dev/shm/<name>.mem
"""

import argparse
import hashlib
import json
import mmap
import os
import re
import struct
import sys
from datetime import datetime, timezone
from pathlib import Path

MANIFEST_VERSION = 1
VMITRACE_MAGIC = 0x4543415254494d56
HDR_FMT = "<QIIIIQQQ"            # include/vmitrace/abi.h, struct vmitrace_hdr
HDR_SIZE = 64
STATE_SIZE = 64
BITMAP_BYTES = 64
PAGE = 0x1000

SHF_WRITE, SHF_ALLOC = 0x1, 0x2
SHT_NOBITS = 8


class Elf:
    """Just enough ELF64 little-endian parsing: sections and .symtab."""

    def __init__(self, path):
        self.data = Path(path).read_bytes()
        d = self.data
        if d[:4] != b"\x7fELF" or d[4] != 2 or d[5] != 1:
            sys.exit(f"{path}: not an ELF64 little-endian file")
        (shoff,) = struct.unpack_from("<Q", d, 0x28)
        shentsize, shnum, shstrndx = struct.unpack_from("<HHH", d, 0x3a)
        raw = [struct.unpack_from("<IIQQQQIIQQ", d, shoff + i * shentsize)
               for i in range(shnum)]
        names = raw[shstrndx]
        self.sections = []
        for (name, typ, flags, addr, off, size, link, info, align,
             entsize) in raw:
            n = d[names[4] + name:d.index(b"\0", names[4] + name)].decode()
            self.sections.append(dict(name=n, type=typ, flags=flags,
                                      addr=addr, offset=off, size=size,
                                      link=link, entsize=entsize))
        self.symbols = {}
        symtab = self.section(".symtab")
        strtab = self.sections[symtab["link"]]
        for i in range(symtab["size"] // 24):
            st_name, st_info, _, st_shndx, st_value, st_size = \
                struct.unpack_from("<IBBHQQ", d, symtab["offset"] + i * 24)
            if not st_name or st_shndx == 0:
                continue
            o = strtab["offset"] + st_name
            n = d[o:d.index(b"\0", o)].decode()
            # first definition wins; duplicates of local names are possible
            self.symbols.setdefault(n, (st_value, st_size))

    def section(self, name):
        for s in self.sections:
            if s["name"] == name:
                return s
        sys.exit(f"section {name} not found")

    def sym(self, name):
        if name not in self.symbols:
            sys.exit(f"symbol {name} not found")
        return self.symbols[name]

    def section_at(self, addr, size):
        for s in self.sections:
            if (s["flags"] & SHF_ALLOC and s["addr"] <= addr
                    and addr + size <= s["addr"] + s["size"]):
                return s
        return None

    def read(self, addr, size):
        s = self.section_at(addr, size)
        if s is None or s["type"] == SHT_NOBITS:
            sys.exit(f"{addr:#x}+{size:#x} is not in a PROGBITS section")
        o = s["offset"] + addr - s["addr"]
        return self.data[o:o + size]


def sha256(b):
    return hashlib.sha256(b).hexdigest()


def read_syscall_nrs(path):
    nrs = {}
    for line in Path(path).read_text().splitlines():
        m = re.match(r"#define SYS_(\w+)\s+(\d+)\s*$", line)
        if m:
            nrs.setdefault(int(m.group(2)), m.group(1))
    return nrs


def read_kconfig(path):
    cfg = {}
    for line in Path(path).read_text().splitlines():
        m = re.match(r"(CONFIG_LIBVMITRACE\w*)=(.*)$", line)
        if m:
            cfg[m.group(1)] = m.group(2).strip('"')
    return cfg


def build_manifest(dbg_path):
    dbg_path = Path(dbg_path).resolve()
    build_dir = dbg_path.parent
    kernel = dbg_path.with_suffix("")          # stripped image QEMU boots
    elf = Elf(dbg_path)

    # --- header ---
    hdr_addr, hdr_size = elf.sym("vmitrace_hdr")
    if hdr_size != HDR_SIZE:
        sys.exit(f"vmitrace_hdr is {hdr_size} bytes, expected {HDR_SIZE}")
    hdr_bytes = elf.read(hdr_addr, HDR_SIZE)
    (magic, version, record_size, capacity, nr_lcpu, state_addr,
     records_addr, bitmap_addr) = struct.unpack_from(HDR_FMT, hdr_bytes)
    if magic != VMITRACE_MAGIC:
        sys.exit(f"bad magic {magic:#x} in image header")
    if hdr_addr % PAGE:
        sys.exit(f"vmitrace_hdr at {hdr_addr:#x} is not page-aligned")

    # --- header pointers must equal the symbols ---
    st_sym, st_size = elf.sym("vmitrace_state")
    rec_sym, rec_size = elf.sym("vmitrace_records")
    bm_sym, bm_size = elf.sym("vmitrace_bitmap")
    for what, h, s in (("state_addr", state_addr, st_sym),
                       ("records_addr", records_addr, rec_sym),
                       ("bitmap_addr", bitmap_addr, bm_sym)):
        if h != s:
            sys.exit(f"header {what}={h:#x} != symbol {s:#x}")
    if st_size != STATE_SIZE * nr_lcpu:
        sys.exit("vmitrace_state size does not match nr_lcpu")
    if rec_size != record_size * capacity * nr_lcpu:
        sys.exit("vmitrace_records size does not match header")
    if bm_size != BITMAP_BYTES:
        sys.exit("vmitrace_bitmap is not 64 bytes")
    for what, addr, size in (("state", st_sym, st_size),
                             ("records", rec_sym, rec_size)):
        s = elf.section_at(addr, size)
        if s is None or s["type"] != SHT_NOBITS:
            sys.exit(f"ring {what} is not in a NOBITS section")
    end_sym = elf.sym("_end")[0]
    ring_end = elf.sym("vmitrace_ring_end")[0]
    if ring_end > end_sym:
        sys.exit(f"ring ends at {ring_end:#x}, after _end {end_sym:#x}")

    # --- bitmap ---
    bm_bytes = elf.read(bm_sym, BITMAP_BYTES)
    words = struct.unpack("<8Q", bm_bytes)
    selected = [n for n in range(512) if words[n >> 6] >> (n & 63) & 1]
    names = read_syscall_nrs(
        build_dir / "libsyscall_shim/include/uk/bits/syscall_nrs.h")
    kcfg = read_kconfig(build_dir / "config")
    groups = sorted(k[len("CONFIG_LIBVMITRACE_GROUP_"):] for k, v in
                    kcfg.items()
                    if k.startswith("CONFIG_LIBVMITRACE_GROUP_") and v == "y")

    # --- hash regions ---
    regions = []

    def add(name, addr, size, kind):
        sec = elf.section_at(addr, size)
        if sec is None or sec["type"] == SHT_NOBITS:
            sys.exit(f"{name}: {addr:#x}+{size:#x} not in PROGBITS")
        if sec["flags"] & SHF_WRITE:
            sys.exit(f"{name}: in writable section {sec['name']}")
        regions.append(dict(name=name, kind=kind, section=sec["name"],
                            addr=addr, size=size,
                            sha256=sha256(elf.read(addr, size))))

    add("vmitrace_hdr", hdr_addr, HDR_SIZE, "header")
    add("vmitrace_bitmap", bm_sym, BITMAP_BYTES, "bitmap")
    vt = elf.section(".vmitrace_text")
    add(".vmitrace_text", vt["addr"], vt["size"], "hook_code")

    hook_tables = {}
    for tab, ours in (("entertab", "vt_enter"), ("exittab", "vt_exit")):
        start = elf.sym(f"uk_syscall_{tab}_start")[0]
        end = elf.sym(f"uk_syscall_{tab}_end")[0]
        if end <= start:
            sys.exit(f"uk_syscall_{tab} is empty")
        add(f"uk_syscall_{tab}", start, end - start, "hook_table")
        entries = struct.unpack(f"<{(end - start) // 8}Q",
                                elf.read(start, end - start))
        fn = elf.sym(ours)[0]
        if fn not in entries:
            sys.exit(f"{ours} ({fn:#x}) is not in uk_syscall_{tab}")
        rev = {}
        for n, (a, _) in elf.symbols.items():
            rev.setdefault(a, n)
        hook_tables[tab] = dict(
            start=start, end=end, ours=ours, ours_addr=fn,
            entries=[dict(addr=e, symbol=rev.get(e)) for e in entries])

    for fn in ("ukplat_syscall_handler", "ukplat_monotonic_clock",
               "uk_sys_gettid"):
        addr, size = elf.sym(fn)
        if not size:
            sys.exit(f"{fn} has no symbol size")
        add(fn, addr, size, "function")

    # --- exclusions: boot page tables in .text, 4 KiB each ---
    excluded = sorted(
        (dict(name=n, addr=a, size=PAGE) for n, (a, _) in elf.symbols.items()
         if n.startswith("x86_bpt_")), key=lambda e: e["addr"])
    if not excluded:
        sys.exit("no x86_bpt_* symbols found")
    for r in regions:
        for e in excluded:
            if r["addr"] < e["addr"] + e["size"] and e["addr"] < r["addr"] + r["size"]:
                sys.exit(f"{r['name']} overlaps boot page table {e['name']}")

    return dict(
        manifest_version=MANIFEST_VERSION,
        generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        generator="tools/gen_manifest.py",
        build_id=sha256(kernel.read_bytes()),
        image=dict(kernel=str(kernel), kernel_sha256=sha256(kernel.read_bytes()),
                   dbg=str(dbg_path), dbg_sha256=sha256(elf.data)),
        address_space=dict(
            note="guest physical address == offset in memory-backend-file"),
        abi=dict(magic=magic, version=version, record_size=record_size,
                 capacity=capacity, nr_lcpu=nr_lcpu, header_size=HDR_SIZE,
                 state_size=STATE_SIZE),
        expected=dict(header_addr=hdr_addr, state_addr=state_addr,
                      records_addr=records_addr, bitmap_addr=bitmap_addr),
        ring=dict(state_addr=st_sym, state_size=st_size,
                  records_addr=rec_sym, records_size=rec_size,
                  start=elf.sym("vmitrace_ring_start")[0], end=ring_end,
                  image_end=end_sym),
        bitmap=dict(addr=bm_sym, size=BITMAP_BYTES, sha256=sha256(bm_bytes),
                    words=[f"{w:#018x}" for w in words],
                    kconfig_groups=groups,
                    selected_count=len(selected),
                    syscalls=[dict(nr=n, name=names.get(n)) for n in selected
                              if n in names],
                    selected_unnamed=[n for n in selected if n not in names]),
        hook_tables=hook_tables,
        hash_regions=regions,
        excluded=excluded,
    )


def check_mem(manifest, mem_path):
    """Compare hash regions and the header with a live guest RAM file."""
    fd = os.open(mem_path, os.O_RDONLY)
    try:
        m = mmap.mmap(fd, 0, prot=mmap.PROT_READ)
    finally:
        os.close(fd)
    bad = 0
    for r in manifest["hash_regions"]:
        got = sha256(m[r["addr"]:r["addr"] + r["size"]])
        ok = got == r["sha256"]
        bad += not ok
        print(f"{'OK  ' if ok else 'DIFF'} {r['name']:24s} {r['addr']:#x}+{r['size']:#x}")
    ring = manifest["ring"]
    widx = struct.unpack_from("<Q", m, ring["state_addr"])[0]
    print(f"write_idx[0]={widx}")
    return bad


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("dbg", help="<build>/nginx_qemu-x86_64.dbg")
    ap.add_argument("-o", "--output",
                    help="default: manifest.json next to the image")
    ap.add_argument("--check-mem", metavar="MEMFILE",
                    help="also compare against a live memory-backend-file")
    args = ap.parse_args()
    man = build_manifest(args.dbg)
    out = Path(args.output) if args.output else Path(args.dbg).resolve().parent / "manifest.json"
    out.write_text(json.dumps(man, indent=2) + "\n")
    print(f"{out}: build_id {man['build_id'][:16]}..., "
          f"{len(man['hash_regions'])} hash regions, "
          f"{man['bitmap']['selected_count']} syscalls selected "
          f"({','.join(man['bitmap']['kconfig_groups'])})")
    if args.check_mem:
        sys.exit(1 if check_mem(man, args.check_mem) else 0)


if __name__ == "__main__":
    main()
