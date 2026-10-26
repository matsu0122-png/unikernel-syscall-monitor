"""Read lib-vmitrace rings out of a shared guest-RAM file (Phase 10-3).

Standard library only, so integrity/ can reuse it. Nothing read from the
guest is trusted:

- Addresses, sizes and constants come from manifest.json; the guest header
  and bitmap are only *compared* with it (byte-for-byte via their sha256;
  header fields are named in the error message). The header carries a
  per-build nonce (ABI v2), so a manifest of another build with the same
  layout does not match.
- Only three windows of the file are mapped, read-only: the page holding
  the 64-byte header, the page holding the 64-byte bitmap, and the ring
  range (state array + records).
- Every record is checked (seq protocol, nr range, lcpu, flags, timestamps);
  rejects are counted, never emitted.

Layout and write protocol: guest/lib-vmitrace/include/vmitrace/abi.h.
"""

import hashlib
import json
import mmap
import os
import struct
from collections import Counter
from dataclasses import dataclass
from typing import List, Optional

PAGE = 4096
HDR_FMT = "<QIIIIQQQQQ"
REC_FMT = "<QQQIHH6QqQ"
REC_SIZE = struct.calcsize(REC_FMT)          # 96
STATE_SIZE = 64
BITMAP_BITS = 512
F_ENTRY_ONLY = 1 << 0
F_NO_ENTER_TS = 1 << 1
F_TID_ERR = 1 << 2
F_KNOWN = F_ENTRY_ONLY | F_NO_ENTER_TS | F_TID_ERR
SYS_EXIT, SYS_EXIT_GROUP = 60, 231
# A ring cannot plausibly advance by more than this between two polls.
MAX_PLAUSIBLE_ADVANCE = 1 << 32

assert REC_SIZE == 96


class ManifestError(Exception):
    pass


class Manifest:
    def __init__(self, path):
        with open(path) as f:
            m = json.load(f)
        if m.get("manifest_version") != 1:
            raise ManifestError(f"{path}: unsupported manifest_version")
        self.path = str(path)
        self.raw = m
        self.build_id = m["build_id"]
        self.abi = m["abi"]
        self.expected = m["expected"]
        self.ring = m["ring"]
        self.capacity = self.abi["capacity"]
        self.nr_lcpu = self.abi["nr_lcpu"]
        if self.abi["record_size"] != REC_SIZE:
            raise ManifestError("record_size in manifest is not 96")
        if self.capacity <= 0 or self.capacity & (self.capacity - 1):
            raise ManifestError("capacity is not a power of two")
        regions = {r["name"]: r for r in m["hash_regions"]}
        self.header_sha256 = regions["vmitrace_hdr"]["sha256"]
        self.bitmap_sha256 = regions["vmitrace_bitmap"]["sha256"]
        self.build_nonce = tuple(int(x, 16) for x in m["build_nonce"])
        words = [int(w, 16) for w in m["bitmap"]["words"]]
        self.selected = frozenset(
            n for n in range(BITMAP_BITS) if words[n >> 6] >> (n & 63) & 1)
        self.syscall_names = {s["nr"]: s["name"]
                              for s in m["bitmap"]["syscalls"]}


@dataclass
class Record:
    lcpu_ring: int
    idx: int
    ts_enter_ns: int
    ts_exit_ns: int
    nr: int
    lcpu: int
    flags: int
    args: tuple
    ret: int
    tid: int
    unselected: bool = False


class GuestRing:
    """Read-only view of the header page and the ring range of one guest."""

    def __init__(self, mem_path, manifest: Manifest):
        self.man = manifest
        self.mem_path = mem_path
        self.counters = Counter()
        exp, ring = manifest.expected, manifest.ring
        fd = os.open(mem_path, os.O_RDONLY | os.O_CLOEXEC)
        try:
            size = os.fstat(fd).st_size
            need = max(ring["end"], exp["header_addr"] + 64)
            if size < need:
                raise ValueError(f"{mem_path} is {size} bytes, ring needs {need}")
            self.hdr_page = exp["header_addr"] & ~(PAGE - 1)
            self._hdr_map = mmap.mmap(fd, PAGE, mmap.MAP_SHARED,
                                      mmap.PROT_READ, offset=self.hdr_page)
            self.bm_page = exp["bitmap_addr"] & ~(PAGE - 1)
            if (exp["bitmap_addr"] + 64 - self.bm_page > PAGE
                    or size < exp["bitmap_addr"] + 64):
                raise ValueError("bitmap crosses a page or the file end")
            self._bm_map = mmap.mmap(fd, PAGE, mmap.MAP_SHARED,
                                     mmap.PROT_READ, offset=self.bm_page)
            self.ring_base = ring["start"] & ~(PAGE - 1)
            ring_len = -(-ring["end"] // PAGE) * PAGE - self.ring_base
            self._ring_map = mmap.mmap(fd, ring_len, mmap.MAP_SHARED,
                                       mmap.PROT_READ, offset=self.ring_base)
        finally:
            os.close(fd)
        self.mapped = [(self.hdr_page, PAGE), (self.bm_page, PAGE),
                       (self.ring_base, ring_len)]
        self.next_idx = [0] * manifest.nr_lcpu
        self.last_widx = [0] * manifest.nr_lcpu

    def close(self):
        self._hdr_map.close()
        self._bm_map.close()
        self._ring_map.close()

    # --- header ---

    def header_status(self):
        """'ok' when header and bitmap both match the manifest,
        'not_loaded' (header all zero: kernel not in RAM yet), or a
        mismatch description. Records must only be read on 'ok'."""
        off = self.man.expected["header_addr"] - self.hdr_page
        raw = bytes(self._hdr_map[off:off + 64])
        if hashlib.sha256(raw).hexdigest() != self.man.header_sha256:
            if raw == bytes(64):
                return "not_loaded"
            f = struct.unpack_from(HDR_FMT, raw)
            names = ("magic", "version", "record_size", "capacity",
                     "nr_lcpu", "state_addr", "records_addr", "bitmap_addr",
                     "build_nonce[0]", "build_nonce[1]")
            want = (self.man.abi["magic"], self.man.abi["version"],
                    self.man.abi["record_size"], self.man.abi["capacity"],
                    self.man.abi["nr_lcpu"], self.man.expected["state_addr"],
                    self.man.expected["records_addr"],
                    self.man.expected["bitmap_addr"]) + self.man.build_nonce
            diff = [f"{n}={g:#x}!={w:#x}" for n, g, w in zip(names, f, want)
                    if g != w]
            return "header mismatch: " + (", ".join(diff) or "?")
        off = self.man.expected["bitmap_addr"] - self.bm_page
        bm = bytes(self._bm_map[off:off + 64])
        if hashlib.sha256(bm).hexdigest() != self.man.bitmap_sha256:
            return "bitmap mismatch"
        return "ok"

    # --- ring ---

    def _u64(self, gpa):
        return struct.unpack_from("<Q", self._ring_map, gpa - self.ring_base)[0]

    def write_idx(self, lcpu):
        return self._u64(self.man.ring["state_addr"] + lcpu * STATE_SIZE)

    def dropped(self, lcpu):
        return self._u64(self.man.ring["state_addr"] + lcpu * STATE_SIZE + 8)

    def poll(self, lcpu) -> List[Record]:
        """Return the new valid records of one lcpu ring, oldest first."""
        cap = self.man.capacity
        c = self.counters
        widx = self.write_idx(lcpu)
        nxt = self.next_idx[lcpu]
        if widx < self.last_widx[lcpu]:
            c["write_idx_regress"] += 1
            nxt = widx
        elif widx - nxt > MAX_PLAUSIBLE_ADVANCE:
            c["write_idx_implausible"] += 1
            nxt = widx
        self.last_widx[lcpu] = widx
        if widx - nxt > cap:
            c["lost_overwritten"] += widx - cap - nxt
            nxt = widx - cap
        out = []
        base = (self.man.ring["records_addr"] - self.ring_base
                + lcpu * cap * REC_SIZE)
        for idx in range(nxt, widx):
            off = base + (idx & (cap - 1)) * REC_SIZE
            seq1 = struct.unpack_from("<Q", self._ring_map, off)[0]
            raw = bytes(self._ring_map[off:off + REC_SIZE])
            seq2 = struct.unpack_from("<Q", self._ring_map, off)[0]
            f = struct.unpack(REC_FMT, raw)
            if not (seq1 == seq2 == f[0] == idx + 1):
                # The writer lapped us while we read (or the slot is junk).
                if self.write_idx(lcpu) - cap > idx:
                    c["lost_overwritten"] += 1
                else:
                    c["bad_seq"] += 1
                continue
            rec = Record(lcpu, idx, f[1], f[2], f[3], f[4], f[5],
                         tuple(f[6:12]), f[12], f[13])
            why = self._invalid(rec, lcpu)
            if why:
                c["invalid_" + why] += 1
                continue
            if rec.nr not in self.man.selected:
                rec.unselected = True
                c["unselected_nr"] += 1
            c["records_ok"] += 1
            out.append(rec)
        self.next_idx[lcpu] = widx
        return out

    @staticmethod
    def _invalid(r: Record, lcpu) -> Optional[str]:
        if r.nr >= BITMAP_BITS:
            return "nr"
        if r.lcpu != lcpu:
            return "lcpu"
        if r.flags & ~F_KNOWN:
            return "flags"
        if r.flags & F_ENTRY_ONLY:
            if r.nr not in (SYS_EXIT, SYS_EXIT_GROUP) or r.ts_exit_ns or r.ret:
                return "entry_only"
            return None
        if r.flags & F_NO_ENTER_TS:
            if r.ts_enter_ns:
                return "ts"
        elif r.ts_enter_ns > r.ts_exit_ns:
            return "ts"
        return None
