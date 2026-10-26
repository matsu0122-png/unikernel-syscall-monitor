# legacy/ — Phase 1-9 (patched-QEMU / gdb mechanisms)

Kept unchanged in behaviour as the comparison baseline for Phase 10. Moved
here from the repo root in Phase 10-2. Path handling was adjusted so they
still resolve the same files:

- `logs/` and `syscall_table.py` stay at the repo root (`REPO = HERE.parent`).
- The guest image is still `../../.unikraft/build/nginx_qemu-x86_64[.dbg]`
  (`PROJECT_DIR = REPO.parent`), i.e. the Phase 1-9 image, untouched.

Run from the repo root, e.g. `python3 legacy/run_capture_inline.py ...`.

| path | phase |
|---|---|
| `attach_gdbstub.py`, `gdb_session.py`, `monitor.py`, `phase1_manual_test.gdb`, `run_capture.py`, `bench_overhead.py` | 1-4 (gdb/RSP) |
| `run_capture_from_boot.py` | 5 |
| `qemu_patch/`, `run_capture_inline.py`, `bench_overhead_inline.py` | 6-9 (patched QEMU 6.2.0) |
