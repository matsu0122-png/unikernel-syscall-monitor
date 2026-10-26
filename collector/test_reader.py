"""Unit tests for vmitrace_reader against a synthetic guest-RAM file.

Covers what a live nginx run never produces: torn/overwritten slots,
invalid fields, entry-only records, header tampering, write_idx going
backwards.

    python3 collector/test_reader.py
"""

import hashlib
import json
import os
import struct
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import vmitrace_reader as vr  # noqa: E402

HDR, BM = 0x3000, 0x2000
STATE, RECS = 0x10000, 0x10040
CAP, NL = 8, 1
SIZE = 0x20000
MAGIC = 0x4543415254494d56


def header_bytes(**over):
    f = dict(magic=MAGIC, version=1, record_size=96, capacity=CAP,
             nr_lcpu=NL, state=STATE, records=RECS, bitmap=BM)
    f.update(over)
    return struct.pack("<QIIIIQQQ", f["magic"], f["version"],
                       f["record_size"], f["capacity"], f["nr_lcpu"],
                       f["state"], f["records"], f["bitmap"]) + bytes(16)


class Fake:
    def __init__(self, tmp, selected=(0, 3, 60, 231, 288)):
        self.path = os.path.join(tmp, "g.mem")
        with open(self.path, "wb") as f:
            f.truncate(SIZE)
        self.fd = os.open(self.path, os.O_RDWR)
        words = [0] * 8
        for n in selected:
            words[n >> 6] |= 1 << (n & 63)
        man = dict(
            manifest_version=1, build_id="x",
            abi=dict(magic=MAGIC, version=1, record_size=96, capacity=CAP,
                     nr_lcpu=NL),
            expected=dict(header_addr=HDR, state_addr=STATE,
                          records_addr=RECS, bitmap_addr=BM),
            ring=dict(start=STATE, end=RECS + CAP * NL * 96,
                      state_addr=STATE, records_addr=RECS),
            hash_regions=[dict(name="vmitrace_hdr",
                               sha256=hashlib.sha256(header_bytes()).hexdigest())],
            bitmap=dict(words=[f"{w:#018x}" for w in words],
                        syscalls=[dict(nr=n, name=f"s{n}") for n in selected]))
        self.man_path = os.path.join(tmp, "manifest.json")
        Path(self.man_path).write_text(json.dumps(man))

    def put(self, off, data):
        os.pwrite(self.fd, data, off)

    def header(self, **over):
        self.put(HDR, header_bytes(**over))

    def widx(self, v):
        self.put(STATE, struct.pack("<Q", v))

    def rec(self, idx, seq=None, nr=3, lcpu=0, flags=0, te=100, tx=200,
            ret=0, tid=2):
        off = RECS + (idx % CAP) * 96
        self.put(off, struct.pack("<QQQIHH6QqQ",
                                  idx + 1 if seq is None else seq, te, tx,
                                  nr, lcpu, flags, 7, 0, 0, 0, 0, 0, ret, tid))

    def ring(self):
        return vr.GuestRing(self.path, vr.Manifest(self.man_path))


class ReaderTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.g = Fake(self.tmp.name)

    def tearDown(self):
        os.close(self.g.fd)
        self.tmp.cleanup()

    def test_header_states(self):
        r = self.g.ring()
        self.assertEqual(r.header_status(), "not_loaded")
        self.g.header()
        self.assertEqual(r.header_status(), "ok")
        self.g.header(records=RECS + 96)            # guest moved its ring
        self.assertIn("records_addr", r.header_status())
        self.g.header()
        self.g.put(HDR + 60, b"\x01")               # reserved byte
        self.assertIn("reserved", r.header_status())

    def test_maps_only_header_page_and_ring(self):
        r = self.g.ring()
        self.assertEqual(r.mapped, [(HDR, 0x1000), (STATE, 0x1000)])

    def test_valid_and_incremental(self):
        self.g.header()
        for i in range(3):
            self.g.rec(i)
        self.g.widx(3)
        r = self.g.ring()
        self.assertEqual([x.idx for x in r.poll(0)], [0, 1, 2])
        self.assertEqual(r.poll(0), [])
        self.g.rec(3, nr=288, ret=7)
        self.g.widx(4)
        (x,) = r.poll(0)
        self.assertEqual((x.idx, x.nr, x.ret, x.args[0]), (3, 288, 7, 7))
        self.assertEqual(r.counters["records_ok"], 4)

    def test_overwrite_loss(self):
        self.g.header()
        for i in range(20):
            self.g.rec(i)
        self.g.widx(20)
        r = self.g.ring()
        got = r.poll(0)
        self.assertEqual([x.idx for x in got], list(range(12, 20)))
        self.assertEqual(r.counters["lost_overwritten"], 12)

    def test_bad_seq_and_invalid_fields(self):
        self.g.header()
        self.g.rec(0, seq=0)                         # in progress / torn
        self.g.rec(1, nr=600)
        self.g.rec(2, lcpu=1)
        self.g.rec(3, flags=0x80)
        self.g.rec(4, te=300, tx=200)
        self.g.rec(5, flags=vr.F_ENTRY_ONLY, nr=3, tx=0)   # not exit*
        self.g.rec(6, flags=vr.F_ENTRY_ONLY, nr=231, tx=0)  # ok
        self.g.rec(7, nr=5)                          # valid but unselected
        self.g.widx(8)
        r = self.g.ring()
        got = r.poll(0)
        self.assertEqual([x.idx for x in got], [6, 7])
        self.assertTrue(got[1].unselected)
        c = r.counters
        self.assertEqual((c["bad_seq"], c["invalid_nr"], c["invalid_lcpu"],
                          c["invalid_flags"], c["invalid_ts"],
                          c["invalid_entry_only"], c["unselected_nr"]),
                         (1, 1, 1, 1, 1, 1, 1))

    def test_no_enter_ts(self):
        self.g.header()
        self.g.rec(0, flags=vr.F_NO_ENTER_TS, te=0)
        self.g.rec(1, flags=vr.F_NO_ENTER_TS, te=5)  # flag says no ts
        self.g.widx(2)
        r = self.g.ring()
        self.assertEqual([x.idx for x in r.poll(0)], [0])
        self.assertEqual(r.counters["invalid_ts"], 1)

    def test_write_idx_regress_and_jump(self):
        self.g.header()
        for i in range(4):
            self.g.rec(i)
        self.g.widx(4)
        r = self.g.ring()
        r.poll(0)
        self.g.widx(2)
        self.assertEqual(r.poll(0), [])
        self.assertEqual(r.counters["write_idx_regress"], 1)
        self.g.widx(1 << 40)
        r.poll(0)
        self.assertEqual(r.counters["write_idx_implausible"], 1)

    def test_short_file_rejected(self):
        with open(self.g.path, "r+b") as f:
            f.truncate(RECS)
        with self.assertRaises(ValueError):
            self.g.ring()


if __name__ == "__main__":
    unittest.main(verbosity=2)
