# Phase 10-1: guest library `lib-vmitrace`

Status: **implemented and smoke-tested** (ALL and NET builds booted on the
distro QEMU). The strace comparison, return-value check, benchmarks and drop
measurements are Phase 10-5. Unikraft itself is unmodified: only the
enter/exit hook tables and a library linker script are used.

## 1. Pinned sources and the new build location

Builds run in `/home/matsu/vmitrace-build/` (outside this repo and outside
the `catalog` repo). `../.unikraft/` and `backup_verified_build/` are not
touched.

`tools/guest_build.py vendor` copies, `tools/guest_build.py build <variant>`
builds:

| vendor/ | copied from |
|---|---|
| `unikraft` | `../.unikraft/unikraft` |
| `libs/lwip` | `../.unikraft/libs/lwip` |
| `libs/libelf` | `../.unikraft/libs/libelf` |
| `apps/elfloader` | `../.unikraft/apps/elfloader` |
| `origin/liblwip` | `../.unikraft/build/liblwip/origin` (extracted + patched lwip) |

`guest/vendor.sha256` has the sha256 of all 2,213 files (sha256 of the list
file itself: `bb48cc82...b224`). `diff -rq` against the sources: identical.
`build` re-checks the vendor tree against this list before every build.

**kraftkit 0.12.16 accepts local paths** for `template.source`,
`unikraft.source` and `libraries.*.source` (absolute paths, no `version:`).
Every Kraftfile line other than the four `source:` blocks is copied from
`../Kraftfile` unchanged.

**Problem found: lib-lwip downloads a moving branch at build time.** Its
`Makefile.uk` fetches `fork-lwip/archive/refs/heads/UNIKRAFT-2_1_x.zip` (no
checksum for that branch). The first build attempt downloaded it, re-applied
the patches over the copied, already-patched tree and failed (`1 out of 3
hunks FAILED`). A fresh download (zip sha256 `1cf15ac8...03af`) plus the same
patches gives a **different** `src/include/lwip/sockets.h` than the copied
tree: `TCP_KEEPIDLE/KEEPINTVL/KEEPCNT` are `0x03/0x04/0x05` instead of
`0x04/0x05/0x06`. So an online rebuild would not reproduce the verified image's
lwip. `guest_build.py` avoids it by seeding the copied tree plus the
`.chksum`/`.origin`/`.patched` stamps (with timestamps ordered so make
considers them up to date); the original build directory had the same three
stamps.

**Baseline check (variant `base`, no lib-vmitrace)**: compared with
`backup_verified_build/`, the `.config` differs only in three paths and
`CONFIG_UK_FULLVERSION` (`0.20.0~1eee9d4` -> `0.20.0`, since vendor/ is not
inside the catalog git repo). Program headers are identical, and so are the
`_ukplat_syscall`/`ukplat_syscall_handler` addresses. The bytes are not
identical: `.rodata` is 32 bytes shorter (version string and embedded paths),
and that shift changes 6,992 bytes of `.text` (displacements). This build is
condition (a) "no instrumentation" for 10-5.

## 2. Library layout

```
guest/lib-vmitrace/
  Config.uk               LIBVMITRACE, _RING_ORDER, _GROUP_{ALL,NET,FILE,TIME}
  Makefile.uk
  Library.uk              same fields as lib-libelf's
  include/vmitrace/abi.h  shared-memory layout (the host contract)
  groups.h                group lists as X-macros over SYS_* names
  vmitrace.c              hooks, header, bitmap
  vmitrace_ring.S         NOBITS storage (state array + rings)
  vmitrace_hdr.lds.S      .vmitrace output section, INSERT AFTER .rodata
  vmitrace_text.lds.S     .vmitrace_text output section, INSERT AFTER .text
```

Unikraft APIs used, all checked in `vendor/unikraft`:
`uk_syscall_entertab_prio` / `uk_syscall_exittab_prio`
(`lib/syscall_shim/include/uk/syscall_{enter,exit}tab.h:101-112`),
`UK_SYSCALL_{ENTER,EXIT}_CTX_BINARY_SYSCALL`, `execenv->regs.__syscall_*`
(`uk/bits/syscall_linuxabi.h`), `SYS_*` (`uk/syscall.h:652` ->
`uk/bits/syscall_nrs.h`), `ukplat_monotonic_clock()` (`uk/plat/time.h:48`),
`ukplat_lcpu_idx()` (`uk/plat/lcpu.h:148/246`), `uk_sys_gettid()`
(`lib/posix-process/include/uk/process.h:68`), `barrier()`
(`uk/arch/lcpu.h:57`), `UK_PRIO_EARLIEST/LATEST` (`uk/prio.h:79-80`),
`__section/__used/__align64` (`uk/compiler.h`, `uk/essentials.h`),
`UK_CTASSERT` (`uk/essentials.h:168`).

### Memory layout (decision 5)

| region | section | contents | written at run time |
|---|---|---|---|
| header | `.vmitrace` (PROGBITS, R segment, page-aligned) | `struct vmitrace_hdr`, 64 B: magic, version, record_size, capacity, nr_lcpu, and the GPAs of state, records and bitmap | never (hashable) |
| bitmap | `.rodata` | 8 x u64 | never (hashable) |
| state | `.bss.vmitrace_ring` (NOBITS, page-aligned) | `struct vmitrace_lcpu_state[nr_lcpu]`: `write_idx`, `dropped` (64 B each) | yes |
| records | same, after state | `nr_lcpu x capacity x 96 B` | yes |
| hook code | `.vmitrace_text` (R E segment) | `vt_enter`, `vt_exit`, `vt_write` | never (hashable) |

Record layout is the 96-byte format from the original spec, unchanged. The
header differs from the original spec: `write_idx`/`dropped` moved into the
per-lcpu NOBITS state (decision 5), and three address fields were added so the
host can locate the other regions from the header alone.

**Deviation found and fixed during the build**: the ring was first a separate
output section placed with `INSERT AFTER .bss`. The link put it **after**
`_end` (`_end = 0xf90000` = its start address). On x86/multiboot this would
still have been reserved, because mkbootinfo derives kernel regions from
PT_LOAD `p_memsz` and `__END` is used only by the fdt/arm/xen paths (checked
with grep). Still, a region past `_end` is fragile, so the storage is now an
input section named `.bss.vmitrace_ring`, which the common script's
`*(.bss.*)` puts inside `.bss`. Result (ALL build): `.bss` = 0xf50000 +
0xa0000, ring 0xf8c000-0xfec040, `_end` = 0xff0000.

### Hook behaviour

- Both hooks return immediately unless `flags` has the BINARY bit and
  `execenv != NULL`. Native in-kernel calls run the same tables with
  `execenv == NULL`.
- Entry: if the bitmap selects `orig_rax`, store `ukplat_monotonic_clock()`
  in a `__thread` slot indexed by `nested_depth`. For `exit`/`exit_group`,
  also write a record with `VMITRACE_F_ENTRY_ONLY` (decision 6).
- Exit: if selected, take the slot (and clear it) and write one record with
  nr, args, ret (= `rax`), both timestamps, lcpu, tid. A missing slot sets
  `VMITRACE_F_NO_ENTER_TS`.
- Write protocol (abi.h): `seq = 0`, barrier, fields, barrier,
  `seq = idx + 1`, barrier, `write_idx = idx + 1`. No atomics: one writer per
  lcpu ring, and ukschedcoop doesn't preempt inside the hook.
- Full ring: overwrite. The guest never blocks. `dropped` counts events the
  guest skipped; with this code nothing increments it. Overwrite loss is
  visible to the host as `write_idx - capacity` and seq gaps.
- The bitmap is read through a `volatile` pointer. Disassembly confirms
  `mov 0xf36ec0(,%rax,8)` in both hooks, so the in-memory bitmap (which the
  integrity checker will hash) is what decides, not a folded constant.

### What the hooks call (from disassembly of the ALL build)

`.vmitrace_text` (0x196650, 0x22a bytes) contains `vt_write`, `vt_enter`,
`vt_exit`. **LTO kept them together in the dedicated section** (an open
question in 10-0). The only outside calls are `ukplat_monotonic_clock`
(`rdtsc`, multiply, update `tsc_base`/`time_base`; no port I/O, no `cpuid`)
and `uk_sys_gettid` (one `%fs:`-relative TLS load). The integrity checker
should also hash these two functions and `ukplat_syscall_handler` (the
caller) — to be done in 10-2/10-6.

## 3. Smoke test (distro QEMU, scratch reader)

Booted via a scratch wrapper (`/usr/bin/qemu-system-x86_64` +
`memory-backend-file,share=on`), port 8090, and read with a throwaway
script (`O_RDONLY`, `PROT_READ`; the real collector is 10-3).

**ALL** (`CONFIG_LIBVMITRACE_GROUP_ALL=y`, bitmap all ones):

- Header valid at 0xf3c000 (magic, ver 1, 96 B, capacity 4096, 1 lcpu).
- After boot: `write_idx=288`, 288 records, 0 bad seq. After 3 curls (all 200): 341
  records, 0 bad seq, `flags` all 0. First record `brk(0) = 0x402421000`
  (tid 2), then `access = -2 ENOENT`, `openat = -2 ENOENT`, ... as in Phase 8.
- The first request matches the Phase 2/4/8 pattern exactly: `accept4 = 7`,
  `epoll_ctl`, `epoll_wait`, `gettimeofday`, `clock_gettime`,
  `recvfrom = 78`, `openat = 8`, `newfstatat = 0`, `pread64 = 612`,
  `writev = 850`, `setsockopt`, `epoll_wait`, ..., `recvfrom = 0`, `close`.
- A blocking call paired correctly: `epoll_wait` before the first curl,
  `<2,495,894.8 us>`.
- 288 boot records versus Phase 7's 289 boot entries: the difference is the
  `epoll_wait` still blocked when the snapshot was taken (written only on
  return; Phase 7 logged entries).
- Unnamed in `syscall_table.py`: 206, 273, 334 (the same 3 Phase 7 noted).

**NET**: bitmap = exactly the 16 NET syscalls. After boot + 3 curls: 26
records, all NET (`socket` 5, `connect` 4, `setsockopt` 4, `bind` 1,
`listen` 2, `socketpair` 1, `accept4` 3, `recvfrom` 6), 0 bad seq.

## 4. Decision 7: unlink right after open

Tried on the running ALL instance: open `/dev/shm/vmiall.mem` `O_RDONLY`,
mmap **only the ring range** (offset 0xf8c000, 1 MiB), `unlink()` the path,
then 3 curls. QEMU kept running, `write_idx` went 341 -> 377 through the
existing mapping, and the tmpfs space (44 MiB) was freed when QEMU exited,
with no cleanup step.

| | wrapper + pidfile cleanup (decided) | unlink after both opened |
|---|---|---|
| stale file / disk use after exit | collector must notice exit | impossible: freed with the last reference |
| who can open guest RAM later | any `vmitrace` member while the VM runs | nobody (path gone) |
| collector or integrity crash/restart | reopen and continue | **cannot reopen**; recovering needs `/proc/<qemu>/fd` (same uid as QEMU) or fd passing from a supervisor |
| integrity tamper test (HMP write) | unaffected | unaffected |
| coordination | none | something must know both readers have opened, and the window before that remains |

**Recommendation: don't adopt as the default.** Losing monitoring
permanently on a reader restart defeats the integrity checker's purpose
(it must outlive collector bugs). Moreover, a missing integrity checker is
then indistinguishable from an attacker who unlinked first. Keep wrapper +
pidfile cleanup. A later option could be a supervisor that opens the file
once and passes fds to both readers (SCM_RIGHTS) before unlinking; not
built.

## 5. Not done in 10-1 / known limitations

- `vmitrace` group (decision 4): `groupadd` needs root and no reader exists
  yet. It belongs with the collector (10-3).
- Moving Phase 1-8 code to `legacy/`: not done yet. Planned with 10-2, when
  tools/ and collector/ start replacing it, so path fixes happen in one
  commit.
- Syscalls blocked at shutdown (e.g. the last `epoll_wait`) are never
  recorded (decision 6).
- RDTSC exiting on this host's KVM: still unverified (root needed).
- Whether kraftkit requires `Library.uk` for a local library: unverified. The
  file is present, copying lib-libelf's fields.
- SMP: still untested (`CONFIG_UKPLAT_LCPU_MAXCOUNT=1`).
- Overhead: not measured yet (10-5).
