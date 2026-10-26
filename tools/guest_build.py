#!/usr/bin/env python3
"""Build the nginx unikernel with or without lib-vmitrace, from pinned sources.

Phase 10 builds never touch ../.unikraft (the tree behind
backup_verified_build/). Instead:

  vendor   copy Unikraft, lib-lwip, lib-libelf, app-elfloader and the
           already-extracted+patched lwip origin out of ../.unikraft into
           <root>/vendor, and write a sha256 of every file to
           guest/vendor.sha256 (plus the source path).
  build    create <root>/<variant>/ (Dockerfile, conf, wwwroot copied from
           ../, Kraftfile = ../Kraftfile with every source pointed at the
           vendor copy, plus lib-vmitrace for non-base variants) and run
           `kraft build`, then tools/gen_manifest.py for non-base variants.

Variants: base (no lib-vmitrace), net, netfd, file, time, all.

    python3 tools/guest_build.py vendor
    python3 tools/guest_build.py build all
"""

import argparse
import os
import shutil
import subprocess
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parent
APP = REPO.parent                       # .../nginx/1.25
UK_SRC = APP / ".unikraft"
LIB_VMITRACE = REPO / "guest" / "lib-vmitrace"
VENDOR_SHA = REPO / "guest" / "vendor.sha256"
DEFAULT_ROOT = Path(os.environ.get("VMITRACE_BUILD_ROOT",
                                   "/home/matsu/vmitrace-build"))

VENDOR_ITEMS = [
    ("unikraft", UK_SRC / "unikraft"),
    ("libs/lwip", UK_SRC / "libs" / "lwip"),
    ("libs/libelf", UK_SRC / "libs" / "libelf"),
    ("apps/elfloader", UK_SRC / "apps" / "elfloader"),
    # lib-lwip fetches a moving branch zip (UNIKRAFT-2_1_x) at build time;
    # a fresh download + patches does not reproduce this tree (Phase 10-1).
    ("origin/liblwip", UK_SRC / "build" / "liblwip" / "origin"),
]

GROUPS = {
    "base": None,
    "net": ["NET"],
    "netfd": ["NETFD"],
    "file": ["FILE"],
    "time": ["TIME"],
    "all": ["ALL"],
}

# (upstream source block in ../Kraftfile, replacement key under vendor/)
SOURCE_SWAPS = [
    ("template:\n  source: https://github.com/unikraft/app-elfloader.git\n"
     "  version: staging", "template:\n  source: {v}/apps/elfloader"),
    ("unikraft:\n  source: https://github.com/unikraft/unikraft.git\n"
     "  version: staging", "unikraft:\n  source: {v}/unikraft"),
    ("  lwip:\n    source: https://github.com/unikraft/lib-lwip.git\n"
     "    version: staging", "  lwip:\n    source: {v}/libs/lwip"),
    ("  libelf:\n    source: https://github.com/unikraft/lib-libelf.git\n"
     "    version: staging", "  libelf:\n    source: {v}/libs/libelf"),
]


def sha256_tree(root):
    out = subprocess.run(
        "find . -type f -print0 | sort -z | xargs -0 sha256sum",
        shell=True, cwd=root, check=True, capture_output=True, text=True)
    return out.stdout


def cmd_vendor(args):
    vendor = args.root / "vendor"
    if vendor.exists():
        sys.exit(f"{vendor} already exists; refusing to overwrite")
    for dst, src in VENDOR_ITEMS:
        if not src.is_dir():
            sys.exit(f"missing {src}")
        (vendor / dst).parent.mkdir(parents=True, exist_ok=True)
        shutil.copytree(src, vendor / dst, symlinks=True)
    sums = sha256_tree(vendor)
    header = "".join(f"# {dst} <- {src}\n" for dst, src in VENDOR_ITEMS)
    VENDOR_SHA.write_text(header + sums)
    print(f"{vendor}: {sums.count(chr(10))} files, hashes in {VENDOR_SHA}")


def check_vendor(vendor):
    lines = [l for l in VENDOR_SHA.read_text().splitlines()
             if not l.startswith("#")]
    if sha256_tree(vendor).splitlines() != lines:
        sys.exit(f"{vendor} does not match {VENDOR_SHA}")


def kraftfile(vendor, groups):
    text = (APP / "Kraftfile").read_text()
    for old, new in SOURCE_SWAPS:
        if old not in text:
            sys.exit(f"../Kraftfile changed; cannot find:\n{old}")
        text = text.replace(old, new.format(v=vendor))
    if groups is not None:
        lines = [f"  vmitrace:\n    source: {LIB_VMITRACE}\n    kconfig:\n",
                 "      CONFIG_LIBVMITRACE: 'y'\n"]
        lines += [f"      CONFIG_LIBVMITRACE_GROUP_{g}: 'y'\n" for g in groups]
        if "ALL" not in groups and "NET" not in groups:
            lines.append("      CONFIG_LIBVMITRACE_GROUP_NET: 'n'\n")
        text = text.replace("\ntargets:", "".join(lines) + "\ntargets:")
    return text


def seed_lwip(vendor, build_dir):
    """Make lib-lwip's fetch/unarchive/patch rules see a finished state.

    Their stamps are .chksum <- zip, .origin <- .chksum,
    .patched <- .origin (unikraft support/build/Makefile.rules). Without the
    zip, make re-downloads it and re-patches the copied tree, which fails.
    The zip's content is irrelevant once the stamps are newer than it.
    """
    lw = build_dir / "liblwip"
    if (lw / ".patched").exists():
        return
    lw.mkdir(parents=True, exist_ok=True)
    shutil.copytree(vendor / "origin" / "liblwip", lw / "origin",
                    symlinks=True)
    (lw / "UNIKRAFT-2_1_x.zip").write_bytes(b"")
    for i, name in enumerate(["UNIKRAFT-2_1_x.zip", ".chksum", ".origin",
                              ".patched"]):
        p = lw / name
        p.touch()
        os.utime(p, (946684800 + i, 946684800 + i))  # 2000-01-01, ordered


def cmd_build(args):
    vendor = args.root / "vendor"
    check_vendor(vendor)
    work = args.root / args.variant
    work.mkdir(parents=True, exist_ok=True)
    for name in ("Dockerfile", "conf", "wwwroot"):
        src, dst = APP / name, work / name
        if dst.exists():
            continue
        (shutil.copytree if src.is_dir() else shutil.copy2)(src, dst)
    (work / "Kraftfile").write_text(kraftfile(vendor, GROUPS[args.variant]))
    seed_lwip(vendor, work / ".unikraft" / "build")
    log = args.root / f"{args.variant}-build.log"
    cmd = ["kraft", "build", "--no-prompt", "--no-update", "--plat", "qemu",
           "--arch", "x86_64", "--log-type", "basic"]
    print(" ".join(cmd), f"(cwd {work}, log {log})")
    with open(log, "w") as f:
        rc = subprocess.run(cmd, cwd=work, stdout=f, stderr=subprocess.STDOUT
                            ).returncode
    img = work / ".unikraft" / "build" / "nginx_qemu-x86_64"
    if rc != 0 or not img.exists():
        sys.exit(f"build failed (rc={rc}), see {log}")
    print(img)
    if GROUPS[args.variant] is not None:
        subprocess.run([sys.executable, str(HERE / "gen_manifest.py"),
                        str(img.with_suffix(".dbg"))], check=True)


def main():
    ap = argparse.ArgumentParser(description=__doc__,
                                 formatter_class=argparse.RawTextHelpFormatter)
    ap.add_argument("--root", type=Path, default=DEFAULT_ROOT)
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("vendor")
    b = sub.add_parser("build")
    b.add_argument("variant", choices=sorted(GROUPS))
    args = ap.parse_args()
    {"vendor": cmd_vendor, "build": cmd_build}[args.cmd](args)


if __name__ == "__main__":
    main()
