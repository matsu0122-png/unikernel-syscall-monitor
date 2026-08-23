# Phase 6 QEMU patch: inline syscall monitor (no gdb/RSP)

Patches QEMU 6.2.0 (matching Ubuntu jammy's `1:6.2+dfsg-2ubuntu6.31`
package -- the exact source this was developed and tested against was
fetched via `apt-get source qemu-system-x86`) to capture `_ukplat_syscall`
hits entirely inside the QEMU/KVM process, replacing the external
gdb/RSP mechanism in `../monitor.py` + `../attach_gdbstub.py`. Full
design rationale: `../docs/phase6_inline_qemu_design.md`.

## What's here

- `target/i386/kvm/vmi-syscall-monitor.c` / `.h` -- new files, the
  monitor implementation (state machine, breakpoint arm/verify/re-verify,
  KVM_EXIT_DEBUG handling, JSONL logging).
- `target/i386/kvm/vmi-syscall-table.h` -- generated from
  `../syscall_table.py` (same source of truth as the gdb-based tool).
- `0001-kvm.c.diff` -- the only change to existing QEMU code: one new
  branch inside `kvm_handle_debug()`, an include, and a
  `vmi_monitor_init()` call at the top of `kvm_arch_init()`. 40
  insertions, 3 deletions.
- `0002-meson.build.diff` -- registers `vmi-syscall-monitor.c` as a
  build source in `target/i386/kvm/meson.build`.

No other QEMU file is touched. `gdbstub.c`, `softmmu/cpus.c`,
`accel/kvm/kvm-accel-ops.c` are untouched -- the existing gdb-based
workflow (`monitor.py`/`attach_gdbstub.py`) keeps working unmodified
against a stock QEMU binary; this is a separate, opt-in code path in a
separately-built QEMU binary.

## Applying and building

```
# 1. Get matching source (or reuse whatever you already extracted):
apt-get source qemu-system-x86   # -> qemu-6.2+dfsg/

cd qemu-6.2+dfsg/target/i386/kvm
patch -p1 < /path/to/qemu_patch/0001-kvm.c.diff   # against target/i386/kvm/kvm.c, run from qemu-6.2+dfsg/
patch -p1 < /path/to/qemu_patch/0002-meson.build.diff
cp /path/to/qemu_patch/target/i386/kvm/vmi-syscall-monitor.{c,h} .
cp /path/to/qemu_patch/target/i386/kvm/vmi-syscall-table.h .

# 2. libslirp-dev is required for -netdev user (kraft's -p host-port
# publishing) but wasn't installable here (no root). Built locally instead:
#   apt-get source libslirp && cd libslirp-4.6.1
#   meson setup build --prefix=$HOME/local-deps/install --libdir=lib
#   ninja -C build install
# then pass that prefix's pkgconfig dir via PKG_CONFIG_PATH below.

cd ../../..   # back to qemu-6.2+dfsg/
mkdir build && cd build
PKG_CONFIG_PATH=$HOME/local-deps/install/lib/pkgconfig \
  ../configure --target-list=x86_64-softmmu --enable-kvm --enable-slirp \
  --disable-werror \
  --firmwarepath=/usr/share/seabios:/usr/share/qemu:/usr/lib/ipxe/qemu:/usr/share/ipxe/qemu
ninja qemu-system-x86_64
```

(The `--firmwarepath` entries point at this host's existing
`seabios`/`qemu-system-data`/`ipxe-qemu` packages -- a plain
`--prefix=/usr/local` build otherwise fails to find `bios-256k.bin` /
`efi-virtio.rom` since those normally ship as data files installed
alongside the system package, which a from-source build doesn't
install.)

## Running

Opt-in via two environment variables read once at QEMU startup
(`vmi_monitor_init()`, called from `kvm_arch_init()`); unset
`VMI_MONITOR_ADDR` and every code path added by this patch is a no-op --
`kvm_handle_debug()` behaves byte-for-byte like stock QEMU.

```
export VMI_MONITOR_ADDR=0x101000     # _ukplat_syscall, resolve via `nm` -- don't hardcode across builds
export VMI_MONITOR_LOG=/path/to/capture.jsonl
kraft run -d -p 8080:80 --name vmiinline --qemu /path/to/build/qemu-system-x86_64 .
```

Or via `../run_capture_inline.py`, which resolves the address with `nm`
itself and wires these up automatically:

```
python3 run_capture_inline.py --name vmiinline --duration 15 \
    --log logs/capture_inline.jsonl \
    --qemu /path/to/build/qemu-system-x86_64
```

A second file, `<VMI_MONITOR_LOG>.debug.log`, gets diagnostic lines
(arm attempts, hits, state transitions) -- needed because kraftkit runs
QEMU with `-daemonize`, which redirects the process's own stdout/stderr
to `/dev/null` once it forks into the background, so `error_report()` /
`info_report()` output alone is invisible for a `kraft run -d` instance.
