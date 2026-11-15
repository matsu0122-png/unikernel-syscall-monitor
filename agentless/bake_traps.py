#!/usr/bin/env python3
"""Bake the selected syscall traps into the image at build time (Phase 11-2).

    python3 agentless/bake_traps.py --group NET
    python3 agentless/bake_traps.py --syscalls connect,socket -o agentless/build/rare

Post-link build step. Input: the built image and its .dbg (default:
../.unikraft/build/nginx_qemu-x86_64{,.dbg}; neither is changed). Output, in
--out-dir (default agentless/build/<selection>/):

  nginx_qemu-x86_64             the image with 0xCC on the tail jump of each
                                selected syscall's case block in
                                uk_syscall6_do_e (the same sites gen_traps.py
                                finds; nothing else differs)
  nginx_qemu-x86_64.traps.json  trap table + "baked": selection, sites,
                                sha256 of the base and the baked image

Only the trap byte goes into the guest, no code. The policy is fixed in the
image: the host cannot forget to arm a selected syscall, and there is no
window between boot and attach.

The guest needs the host to run: a baked 0xCC is a #BP. With
agentless/qemu-trap.sh as kraft's QEMU, vmi_trap.py registers every baked
site with QEMU's gdbstub before the guest runs its first instruction; KVM
then turns each hit into a VM exit for the host. Without it, the first
selected syscall raises #BP inside the guest, which crashes (fail-closed:
the selected syscalls never run unobserved).

    kraft run --qemu agentless/qemu-trap.sh -p 8080:80 \\
        agentless/build/net/nginx_qemu-x86_64 -a /usr/bin/nginx
"""

import argparse
import hashlib
import json
import os
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
from gen_traps import Elf, build_table, select  # noqa: E402

BUILD = HERE.parent.parent / ".unikraft" / "build"
IMAGE = "nginx_qemu-x86_64"


def sha256(data):
    return hashlib.sha256(data).hexdigest()


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawDescriptionHelpFormatter)
    ap.add_argument("--image", default=str(BUILD / IMAGE), help="built image (ELF32 multiboot)")
    ap.add_argument("--dbg", help="its .dbg (default: <image>.dbg)")
    sel = ap.add_mutually_exclusive_group(required=True)
    sel.add_argument("--group", help="NET, NETFD, FILE, TIME, ALL (guest/lib-vmitrace/groups.h)")
    sel.add_argument("--syscalls", help="comma-separated names, e.g. connect,socket")
    ap.add_argument("-o", "--out-dir", help="default agentless/build/<group or names>")
    a = ap.parse_args()

    image_path = Path(a.image)
    dbg_path = Path(a.dbg or f"{a.image}.dbg")
    table = build_table(dbg_path)
    nrs = select(table, a.group, a.syscalls)
    label = a.group.lower() if a.group else a.syscalls.replace(",", "-")
    out_dir = Path(a.out_dir or HERE / "build" / label)

    img = Elf(image_path)
    dbg = Elf(dbg_path)
    if img.data[4] != 1:
        raise SystemExit(f"{image_path}: expected the ELF32 boot image, not the .dbg")

    # The image must hold exactly the code the table was made from, unpatched.
    d, c = table["dispatcher"], table["caller"]
    regions = [("dispatcher", d["addr"], d["size"]),
               ("jump_table", d["table"], (d["nr_max"] + 1) * 8),
               ("caller", c["addr"], c["size"])]
    for name, base, n in regions:
        if img.read(base, n) != dbg.read(base, n):
            raise SystemExit(f"{image_path}: {name} differs from {dbg_path}; "
                             "not the same build, or already baked")

    sites = {}                          # site address -> nrs that reach it
    for nr in nrs:
        s = table["sites"][str(nr)]
        sites.setdefault(s["site"], []).append(nr)
    # A shared case block traps every nr that uses it: record them all.
    for addr in list(sites):
        sites[addr] = sorted(int(nr) for nr, s in table["sites"].items() if s["site"] == addr)
    baked_nrs = sorted(nr for v in sites.values() for nr in v)
    extra = sorted(set(baked_nrs) - set(nrs))
    if extra:
        print(f"note: shared case blocks also trap nrs {extra}", file=sys.stderr)

    data = bytearray(img.data)
    for addr in sites:
        off = img.offset(addr)
        if data[off] != 0xE9:
            raise SystemExit(f"site {addr:#x}: byte {data[off]:#x}, expected 0xe9")
        data[off] = 0xCC

    out_dir.mkdir(parents=True, exist_ok=True)
    out_img = out_dir / IMAGE
    tmp = out_img.with_suffix(".tmp")
    tmp.write_bytes(data)
    os.chmod(tmp, 0o755)
    tmp.replace(out_img)

    table["baked"] = {
        "selection": a.group.upper() if a.group else a.syscalls,
        "nrs": baked_nrs,
        "names": [table["sites"][str(nr)]["name"] for nr in baked_nrs],
        "sites": sorted(sites),
        "image": str(out_img.resolve()),
        "image_sha256": sha256(data),
        "base_image": str(image_path.resolve()),
        "base_image_sha256": sha256(img.data),
        "entry": img.entry,
    }
    manifest = Path(f"{out_img}.traps.json")
    manifest.write_text(json.dumps(table, indent=1) + "\n")
    print(f"baked {len(sites)} traps ({','.join(table['baked']['names'])}) -> {out_img}")
    print(f"manifest -> {manifest}")


if __name__ == "__main__":
    main()
