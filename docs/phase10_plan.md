# Phase 10 plan: remaining steps and verification items

Tracks what is still to do after each step, including requirements added
while reviewing earlier steps. Results go into README as "Phase 10-x result".

## 10-3 collector (done; README Phase 10-3 result and follow-ups)

- Create group `vmitrace` (root: `groupadd vmitrace`, `usermod -aG vmitrace
  <qemu user>,<collector user>,<integrity user>`); wrapper already chgrps if
  the group exists.
- Open the shared file `O_RDONLY`, mmap with `PROT_READ` **only the ring
  range** (`manifest.ring.start`..`end`, page-aligned) plus the header page.
- Never trust the header: compare magic/version/record_size/capacity/nr_lcpu
  and `state_addr`/`records_addr`/`bitmap_addr` with `manifest.abi` and
  `manifest.expected`; refuse to start on mismatch. Validate every record
  (seq protocol, nr < 512, flags), count rejects.
- Outputs: legacy-compatible JSONL (`validate_strace.py` must work) and OTel
  spans (time offset = min(host - guest) per decision 3).
- Delete the shared file and its `.json` after QEMU exits (pidfile).

## 10-4 Jaeger

- Done (see README Phase 10-4 result).

## 10-5 verification (done; README Phase 10-5 result)

1. Correctness: ALL build vs `logs/strace_ground_truth.log`, offset-0, from
   the first syscall.
2. Selective recording: NET build records nothing outside NET.
3. Return values: Phase 8 values (openat=ENOENT run, pread64=612,
   writev=850, ...).
4. Performance: `ab -n 300 -c 5`, 3 reps (as `legacy/bench_overhead_inline.py`):
   (a) `base` build, (b) NET, (c) ALL, next to the legacy Phase 8 numbers.
5. Loss under load: `dropped` (always 0 in ABI v1) and overwrite loss
   derived from `write_idx`/seq versus ring capacity.
6. **(added at 10-2) Loss rate as a function of ring capacity
   (`LIBVMITRACE_RING_ORDER`), collector polling interval and load**
   (request rate / concurrency): measure the fraction of records lost to
   overwrite for a grid of these three, and report the capacity/poll
   interval needed for zero loss at the measured peak syscall rate.
7. **(added after 10-3) NET vs NETFD**: same workload on both builds;
   compare record count per request, throughput (as item 4), and trace
   completeness: connections opened vs closed by `close` /
   `eof_or_shutdown` / `idle` / `fd_reused` / `open_at_flush` (collector
   `traces` stats), and the share of a request's syscalls that land in its
   connection trace.
8. **(added after 10-3) Every reported run includes the collector's
   `offset_resets`** (and `offset_samples`, `offset_uncertainty_ns`) from
   `--stats`. A non-zero `offset_resets` must be explained (clock drift or a
   violated assumption) before that run's timestamps are used.

## 10-6 integrity

- Separate process and user (group `vmitrace`). Periodically hash every
  `manifest.hash_regions` entry in guest RAM, check `write_idx` advances,
  check the header against `manifest.expected`. Report anomalies as OTel
  events.
- Test: overwrite the bitmap in guest memory (HMP, test only) and confirm
  detection. Also test the hook tables (`uk_syscall_entertab/exittab`).
- **(added before 10-3) Consistency checks** (catch bypasses that leave
  every hashed byte intact, see README "Limits"):
  - traffic is flowing (host-side connection/packet counters, e.g. QEMU
    slirp hostfwd connections or `ss` on the forwarded port) but
    `write_idx` does not advance -> alert;
  - number of connections seen on the host vs number of recorded
    `accept4` returning >= 0 over the same window -> alert on mismatch
    beyond what overwrite loss explains.
