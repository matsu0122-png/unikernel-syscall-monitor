# Phase 10-0 (investigation only): moving to an unmodified QEMU

Status: **investigation complete, no implementation code written.** All
citations are against the sources actually present on this host:

- Unikraft: `../.unikraft/unikraft/` (the tree the current image was built from)
- QEMU: `/home/matsu/qemu-vmi-syscall-monitor/qemu-6.2-vmi/` (read only; the
  files cited here, `hw/i386/multiboot.c`, `hw/core/loader.c`,
  `hw/i386/pc_piix.c`, are not touched by `qemu_patch/`, which only changes
  `kvm.c`, `meson.build` and `fw_cfg.c`)
- Distro QEMU used for the live tests: `/usr/bin/qemu-system-x86_64`,
  `QEMU emulator version 6.2.0 (Debian 1:6.2+dfsg-2ubuntu6.31)`

"Unverified" (未確認) marks anything not confirmed against source or by a run.

## 1. Unikraft version and the syscall hook API

**Version**: `../.unikraft/unikraft/version.mk` says `UK_VERSION=0`,
`UK_SUBVERSION=20`, `UK_EXTRAVERSION=0` (codename Kiviuq), i.e. **0.20.0**.
`.unikraft/build/config` reports `Unikraft/0.20.0~1eee9d4`, but `1eee9d4`
is **not** a Unikraft commit: `.unikraft/unikraft/` has no `.git` of its own,
so `support/scripts/gitsha1` picked up the enclosing `catalog` repo's HEAD
(`1eee9d4 feat(workflows): Evenly split up examples...`). The exact upstream
Unikraft commit (Kraftfile says `version: staging`) is **unverified**.

**Registration macros** (`lib/syscall_shim/include/uk/syscall_entertab.h`
and `syscall_exittab.h`, lines 101-112 in each):

```c
typedef void (*uk_syscall_entertab_func_t)(struct uk_syscall_enter_ctx *);
typedef void (*uk_syscall_exittab_func_t)(struct uk_syscall_exit_ctx *);

uk_syscall_entertab_prio(fn, prio);   /* -> static const entry in section ".uk_syscall_entertab" #prio */
uk_syscall_exittab_prio(fn, prio);    /* -> ".uk_syscall_exittab" #prio */
```

`prio` is a `UK_PRIO_*` value (`<uk/prio.h>`); the in-tree users are
`binary_syscall_debug_handler` (`UK_PRIO_EARLIEST`, enter table) and
`binary_syscall_strace` (`UK_PRIO_LATEST`, exit table) in
`lib/syscall_shim/uk_syscall_binary.c:141,179`. The tables are collected by
`syscall_entertab.lds.S` / `syscall_exittab.lds.S`
(`KEEP(*(SORT_BY_NAME(.uk_syscall_entertab[0-9])))`, `INSERT AFTER .rodata`).
An external library uses exactly the same macro; nothing in Unikraft has to
change. In the current image both tables are empty
(`uk_syscall_entertab_start == _end == 0xf3cd00`).

**Context passed to a hook**:

```c
struct uk_syscall_enter_ctx {        /* exit_ctx is identical */
	struct ukarch_execenv *execenv;
	unsigned long nested_depth;
	__u32 flags;                     /* UK_SYSCALL_{ENTER,EXIT}_CTX_BINARY_SYSCALL = 1<<0 */
};
```

From `execenv->regs` (`lib/syscall_shim/include/uk/bits/syscall_linuxabi.h`
on x86_64): `__syscall_rsyscall` = `orig_rax` (number),
`__syscall_rarg0..5` = `rdi, rsi, rdx, r10, r8, r9`, `__syscall_rret0` = `rax`.

**Two callers, and the hook must tell them apart**:

| caller | file | execenv | flags |
|---|---|---|---|
| binary syscall (`syscall` insn -> `_ukplat_syscall` -> `ukplat_syscall_handler`) | `uk_syscall_binary.c:100-112` | trap frame | `BINARY_SYSCALL` |
| native call of `uk_syscall_e_*/r_*` from inside Unikraft | `tabs.c:11-35`, called from `uk/syscall.h:293,300,401,406,459,465` | **`NULL`** in the non-`_E_` variants | `0` |

So the hook must check `flags & UK_SYSCALL_*_CTX_BINARY_SYSCALL` (and that
`execenv != NULL`) before reading registers. This is the same filter
`binary_syscall_strace` uses, i.e. the same set of events as
`logs/strace_ground_truth.log`. The binary dispatcher calls `uk_syscall_do_*`
(no tables), so a binary syscall is seen exactly once.

Consequence for `syscall_translation_notes.txt` §15 (native-mode apps): the
native path does run the tables, but with `execenv == NULL` and no syscall
number in the context. Native-mode coverage through these hooks is therefore
**not** possible without changing Unikraft; out of scope here.

**At exit**, `orig_rax` and the argument registers are still the saved
trap-frame values and `rax` has already been overwritten with the return
value (`uk_syscall_binary.c:106`), so the exit hook alone can build the
complete record (nr, args, ret), exactly as `binary_syscall_strace` does.
The entry hook only needs to save the entry timestamp.

**TLS in the hook**: with `CONFIG_LIBSYSCALL_SHIM_HANDLER_ULTLS=y` (set),
the handler switches to Unikraft's TLS *before* the enter table
(`uk_syscall_binary.c:93-98`) and back *after* the exit table (114-116).
`__thread` variables in the hook are therefore Unikraft-side per-thread
storage; `uk_syscall_nested_depth` itself is such a variable (`tabs.c:9`).
Because the scheduler switches threads (and TLS) while a syscall blocks, an
entry timestamp stored in a `__thread` slot is still the right one when the
same thread's exit hook runs: blocking calls (`epoll_wait`) pair correctly.
To be safe against nesting I propose indexing a small per-thread array by
`nested_depth` rather than a single slot (binary syscalls cannot nest, so in
practice only one slot is used).

**Other values available in the hook**:

- tid: `pid_t uk_sys_gettid(void)` (public, `lib/posix-process/include/uk/process.h:68`).
  With `CONFIG_LIBPOSIX_PROCESS_MULTITHREADING=y` it returns
  `pthread_self->tid`, a `__thread` read (`process.c:649-655`), or `-ENOTSUP`
  if the thread has no posix_thread. `ukthread2tid()` exists but is declared
  only in the private `lib/posix-process/process.h:120`; not to be used.
- lcpu: `ukplat_lcpu_idx()` (`include/uk/plat/lcpu.h:148`); without
  `CONFIG_HAVE_SMP` (this build) it is the macro `(0)` (line 246).

**Linker placement of a dedicated section**: a library may list a `*.lds.S`
in its `_SRCS-y`; `buildrule_S_lds` preprocesses it and, for a library with no
`_PLATS`, `add_lds_to_lib` appends it to `EXTRA_LD_SCRIPT-y`
(`support/build/Makefile.rules:728-760`), which the KVM link adds as
`-Wl,-T,<script>` (`plat/kvm/Linker.uk:45-48`). This is how syscall_shim
places its own tables, so `.vmitrace` can be placed the same way with an
`INSERT AFTER/BEFORE` script and no platform change.

LTO is on (`CONFIG_OPTIMIZE_LTO=y`). The syscall_shim tables survive LTO with
`__used` + `KEEP`, so a hook registered the same way will too. For the
manifest's "instrumentation code range" the hook functions should get
`__attribute__((section(".text.vmitrace")))` so their bytes are contiguous and
findable; whether LTO keeps that grouping is to be checked in 10-1
(unverified).

## 2. Is everything live before the first syscall (`brk`)?

- **Hooks**: the tables are `static const` data in the image (next to
  `.rodata`). There is no registration call at run time; the hook is active
  as soon as the image is in RAM, which is before any guest instruction runs.
  `brk` (Phase 7's first syscall) is a binary syscall through
  `ukplat_syscall_handler`, so it runs both tables.
- **`.bss` zeroing**: the kvm/x86 boot code has no `memset` of `.bss`
  (checked `plat/kvm/x86/*.S|*.c`, `plat/common`; only the Xen/arm ports do
  it). It relies on the loader. Traced in QEMU:
  - The image kraftkit passes is **ELF32 (i386)** wrapping the ELF64, made by
    `support/scripts/multiboot.py`. Its multiboot header at file offset 52 is
    12 bytes, `flags = 0x3` (PAGE_ALIGN | MEMORY_INFO), **no
    `MULTIBOOT_HEADER_HAS_ADDR`**.
  - So `load_multiboot()` takes the ELF branch (`hw/i386/multiboot.c:191-217`):
    the `EM_X86_64` rejection does not fire because `e_machine` is `EM_386`;
    `load_elf()` registers one ROM per PT_LOAD with `datasize = p_filesz`,
    `romsize = p_memsz`; `rom_copy()` then builds the kernel buffer and
    `memset`s the `romsize - datasize` tail to 0 (`hw/core/loader.c:1370-1385`).
  - The `.bss` (0xf4f000, 0x40000 bytes) is inside the third PT_LOAD
    (`FileSiz 0x44d8`, `MemSiz 0x45000`), so it is zero in the buffer that
    the multiboot DMA option ROM copies into guest RAM (Phase 7 §2) before
    the kernel's first instruction.
  - **Conclusion**: a ring in `.bss` is zero before the first syscall.
    Note it is "zero", not "initialized": no header magic until guest code
    writes it. See the design question in §7.
- **Correction to `docs/phase7_boot_sync_investigation.md` §1**: that document
  says the header has `MULTIBOOT_HEADER_HAS_ADDR` set and that the ELF branch
  cannot be the one taken. The bytes of the image in use say otherwise (above).
  Phase 7's actual mechanism (hooking `fw_cfg_dma_transfer()` for
  `FW_CFG_KERNEL_DATA`) holds for both branches, since both end in
  `fw_cfg_add_bytes(..., FW_CFG_KERNEL_DATA, mbs.mb_buf, ...)`, so this
  doesn't invalidate Phase 7's result. Only the explanation of how the buffer
  is built was wrong. Phase 7's doc has been left unchanged; this note is the record.

## 3. A clock that is safe in the hook

`__nsec ukplat_monotonic_clock(void)` (`include/uk/plat/time.h:48`) ->
`tscclock_monotonic()` (`plat/kvm/x86/time.c:48-51`,
`plat/kvm/x86/tscclock.c:199-213`): one `rdtsc`, a 64x32 multiply, and two
stores to static globals. No port I/O (the PIT/RTC `outb`/`inb` in the same
file are only in `tscclock_init()`/`ukplat_time_init()` and the one-shot timer
programming). It is what `gettimeofday` uses, which syscall_translation_notes
§21 already relies on as "no VM exit". `ukplat_wall_clock()` is the same plus
a constant `rtc_epochoffset`.

- **Unverified**: that KVM on this host does not set RDTSC exiting (normally
  it doesn't). Confirming needs `perf kvm stat` or a `kvm_exit` tracepoint,
  both root-only; not done.
- `tscclock_monotonic()` writes `time_base`/`tsc_base` without locking. Fine
  with 1 lcpu and the cooperative scheduler; a known Unikraft limitation for SMP.
- Guest -> host time conversion: `rtc_epochoffset` comes from the CMOS RTC
  (1 s resolution, `rtc_boot` read once), so `ukplat_wall_clock()` can be off
  by up to ~1 s. Live test (§4): `time_base` is readable from the host, so
  the collector can establish its own offset. See §7 question 3.

## 4. kraftkit's QEMU argv and coexisting with `memory-backend-file`

Run on 2026-10-26 with the **unmodified** distro QEMU, via a probe wrapper in
the scratchpad that logs argv and adds two options (`kraft run -d --qemu
<wrapper> -p 8090:80 --name vmiprobe .`, image md5
`b88ba2bc...` = `backup_verified_build/`). The week-old `vmiinline` instance
on :8080 (patched QEMU) was left alone.

kraftkit calls the binary three times: `-version`, `-accel help`, then the real
launch:

```
-append "/usr/bin/nginx " -cpu host,+x2apic,-pmu -daemonize
-device virtio-net-pci,mac=...,netdev=hostnet0 -device pvpanic -device sga
-display none -enable-kvm -kernel .../.unikraft/build/nginx_qemu-x86_64
-machine pc,accel=kvm -m size=64M -monitor unix:.../mon.sock,server,nowait
-name <machine_id> -netdev user,id=hostnet0,hostfwd=tcp::8090-:80
-nographic -no-reboot -S -parallel none -pidfile .../machine.pid
-qmp unix:.../ctrl.sock,server,nowait -qmp unix:.../evnt.sock,server,nowait
-rtc base=utc -serial file:.../vm.log -smp cpus=1,threads=1,sockets=1 -vga none
```

(No `-initrd` this time, unlike the command line quoted in the Phase 7 doc;
why kraftkit omitted it is unverified. HTTP worked either way.)

Appended by the wrapper, only when `-kernel` is present:

```
-object memory-backend-file,id=vmimem,size=64M,mem-path=/dev/shm/vmiprobe.mem,share=on
-machine memory-backend=vmimem
```

Result: QEMU accepted the second `-machine` (merged with kraftkit's), the
process was `/usr/bin/qemu-system-x86_64`, 3x `curl localhost:8090/` returned
`200`, 612 bytes. `/dev/shm/vmiprobe.mem` was created, 67,108,864 bytes, mode
`0640 matsu:matsu`. The backend `size` must equal `-m` (64M); the wrapper
must derive it from kraftkit's `-m size=...`.

**The file outlives the VM**: still present after `kraft stop` and after
`kraft rm`. It contains the whole guest RAM, including stale ring data with a
valid magic. The wrapper must create it fresh (remove before exec), and
something must delete it afterwards. (Deleted by hand after this test.)

## 5. File offset <-> guest physical address <-> symbol address

Compared every allocated ELF section of `nginx_qemu-x86_64.dbg` against the
live `/dev/shm/vmiprobe.mem` at `offset = sh_addr`, read with
`os.open(O_RDONLY)` + `mmap(PROT_READ)` as user `matsu` (no root):

- `.rodata` (0xda4b58 bytes) and all 14 other read-only sections, plus `.tdata`:
  **byte-identical**.
- `.text`: 37 bytes differ, **all in boot-time-written data that lives in
  `.text`**: the boot page tables `x86_bpt_pml4/pdpt0/pdpt511/pd0_0/pt0_0_0`
  (34 runs) and one relocation in `lcpu_start32` (`do_uk_reloc32`). Nothing
  on the syscall path.
- `.data`, `.uk_bootinfo`, `.posix_socket_driver_list`, `.bss`: differ, as
  expected for writable data.
- Liveness: `time_base` (`.bss`, 0xf50018) read twice 1.24 s apart advanced
  by 1.243 s, so guest writes are visible to the host mmap immediately.

So **symbol address = guest physical address = file offset**: the ELF's
VirtAddr equals PhysAddr, and the early page tables identity-map the image.
**PCI hole**: no effect. `pc_piix.c:147-152` puts all RAM below 4 GiB when
`ram_size < lowmem` (lowmem is 0xe0000000/0xc0000000), and 64 MiB is far
below. (Above ~3 GiB the file would map GPA `4G+x` at offset `lowmem+x`.)

For integrity hashing: hash ranges must exclude the page tables inside
`.text`; hashing only `.text.vmitrace`, the two hook tables and the bitmap
avoids the problem.

## 6. Multiple vCPUs: proposal

Current build: `CONFIG_UKPLAT_LCPU_MAXCOUNT=1`, no `CONFIG_HAVE_SMP`,
kraftkit `-smp cpus=1`. So `nr_lcpu = 1` today, and nothing here is tested
on SMP.

**Proposed: one ring per lcpu** (header gains a per-lcpu array of
`{offset, write_idx, dropped}`, ring `i` written only by lcpu `i`).

- The writer is single-producer per ring: plain stores plus a compiler
  barrier and the "seq last" rule, no `lock`-prefixed instruction on the
  hot path. On x86 (TSO) stores are seen in program order by the host reader.
- A thread that blocks on lcpu 0 and resumes on lcpu 1 is still paired
  correctly, because the entry time is in the thread's TLS and the record
  is written once, at exit, into the exit lcpu's ring.
- The single-writer assumption needs "no preemption inside the hook", which
  holds with `ukschedcoop` (cooperative). Interrupt handlers don't make
  binary syscalls.
- Host side merges rings by `ts_exit_ns`.

The alternative, one shared ring with `__atomic_fetch_add(&write_idx)`,
needs a locked RMW per syscall and lets slow writers leave holes that the
reader has to tell apart from torn records. I'd only choose it if a single
total order across lcpus were required, which it isn't for this tool.

For now: implement the per-lcpu layout with `nr_lcpu = CONFIG_UKPLAT_LCPU_MAXCOUNT`
(=1), so SMP needs no format change later.

## 7. Open design questions (need a decision before 10-1)

1. **Phase numbering**: README already has a committed "Phase 9: overhead
   breakdown" (7aaed2c). The new work is also called Phase 9-x.
2. **Where the new build gets Unikraft**: Kraftfile pins `version: staging`
   (a moving branch). A fresh build in a new directory would refetch a
   possibly newer Unikraft, so 10-5's comparison against Phase 7/8 would mix
   versions. Proposal: copy `../.unikraft/unikraft`, `libs/lwip`,
   `libs/libelf`, `apps/elfloader` into the new build directory and point the
   Kraftfile at the local copies. (Whether kraftkit 0.12.16 accepts local
   paths for `unikraft.source`/`libraries.*.source` is unverified.) Also,
   `../.unikraft/build/config` currently has `CONFIG_LIBSYSCALL_SHIM_STRACE=y`
   left over from Phase 4 even though the binary is the non-strace backup,
   so rebuilding in place would silently produce an strace build.
3. **Guest -> host time**: the guest only has `ukplat_monotonic_clock()` (ns
   since boot) with no precise host anchor (the RTC offset has 1 s
   resolution). Proposal: the collector computes `offset = host_now -
   guest_ts` from newly appeared records and keeps the minimum, which bounds
   the error by the polling delay. Alternative: put `ukplat_wall_clock()` in
   the record and accept ~1 s absolute error.
4. **File permissions / separate user**: the shared file is the *entire* guest
   RAM (TLS keys, request bodies...), created `0640` by the QEMU user. For
   collector and integrity checker to run as other users, the wrapper must
   `chgrp` it to a group they share (or set a umask/ACL). Granting another user
   read access to all guest memory is a security trade-off of its own. Which
   user/group layout do you want?
5. **Header location**: in `.bss` the ring is zero until guest init writes the
   header, so the host can't tell "not booted yet" from "tracer missing".
   Proposal: header in `.vmitrace` as PROGBITS with static initializers
   (magic, version, record_size, capacity, nr_lcpu valid from image load,
   hashable by the manifest), records in a NOBITS part (zero-filled by the
   loader, §2). This needs no init code before `brk`.
6. **Syscalls that never return** (`exit_group`, the `epoll_wait` blocked at
   shutdown) produce no record if records are written only at exit. Phase 8
   logged them as `unfinished`. Option: for a small fixed set (`exit`,
   `exit_group`), also write an entry-only record with a flag.
7. **Stale shared file**: the wrapper deletes `/dev/shm/<name>.mem` before
   exec and the collector deletes it after QEMU exits. OK to have the collector
   delete it, or should cleanup be only in the wrapper?

## 8. Decisions (answers to §7, 2026-10-26)

1. The new work is **Phase 10** (10-0 = this investigation). The earlier
   "Phase 9: overhead breakdown" keeps its name.
2. Unikraft, lib-lwip, lib-libelf and app-elfloader are **copied locally**
   from `../.unikraft/`, with the source path and a sha256 of every file
   recorded. Builds go in a new directory. First check whether kraftkit
   accepts local paths, and report if it doesn't.
3. Records carry the guest's `ukplat_monotonic_clock()`. The collector uses
   min(host time - guest time) as the offset.
4. Dedicated group `vmitrace`, shared file `0640`, collector and integrity
   checker in that group. The collector mmaps only the ring range. The
   "group members can read all guest RAM" trade-off goes in the README.
5. Header = initialized PROGBITS. Records = NOBITS. `write_idx` and `dropped`
   are per-vCPU arrays in the NOBITS part, and only the constant header part is
   hashed.
6. `exit` and `exit_group` also get an entry-time record with a flag.
   Syscalls blocked at shutdown are not recorded (known limitation).
7. Pre-launch removal by the wrapper. Post-exit removal by the collector,
   which detects QEMU exit via the pidfile. Also evaluate "unlink right after
   both processes have opened it" and report.
