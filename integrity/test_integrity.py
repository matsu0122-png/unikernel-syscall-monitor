"""Unit tests for integrity/vmitrace_integrity.py on a synthetic guest RAM file.

All 9 hash regions of a real manifest are laid out in a sparse file with
their real names; the tests modify bytes in that file (as a guest would
modify its own RAM) and drive Checker.check_once() directly. Host-side
connections come from an injected source instead of /proc/net/tcp.

    python3 integrity/test_integrity.py
"""

import hashlib
import json
import os
import random
import struct
import sys
import tempfile
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(HERE.parent / "collector"))

import vmitrace_integrity as vi  # noqa: E402
from vmitrace_reader import GuestRing, Manifest  # noqa: E402

SIZE = 0x20000
MAGIC = 0x4543415254494d56
NONCE = (0x1111222233334444, 0x5555666677778888)
CAP = 8
HDR, BM, STATE, RECS = 0x3000, 0x2000, 0x10000, 0x10040
SYS_ACCEPT4 = 288
# name -> (addr, size), sizes as in the real ALL build
LAYOUT = {
    "vmitrace_hdr": (HDR, 0x40),
    "vmitrace_bitmap": (BM, 0x40),
    ".vmitrace_text": (0x4000, 0x22a),
    "uk_syscall_entertab": (0x5000, 0x8),
    "uk_syscall_exittab": (0x5008, 0x8),
    "ukplat_syscall_handler": (0x6000, 0x322),
    "ukplat_monotonic_clock": (0x7000, 0x50),
    "uk_sys_gettid": (0x7100, 0x17),
    "_ukplat_syscall": (0x8000, 0xdc),
}


def header_bytes(nonce=NONCE):
    return struct.pack("<QIIIIQQQQQ", MAGIC, 2, 96, CAP, 1, STATE, RECS, BM,
                       *nonce)


def bitmap_bytes(selected=(3, 45, 232, 288)):
    words = [0] * 8
    for n in selected:
        words[n >> 6] |= 1 << (n & 63)
    return struct.pack("<8Q", *words)


class FakeGuest:
    def __init__(self, tmp):
        self.path = os.path.join(tmp, "g.mem")
        with open(self.path, "wb") as f:
            f.truncate(SIZE)
        self.fd = os.open(self.path, os.O_RDWR)
        rng = random.Random(42)
        self.content = {}
        for name, (addr, size) in LAYOUT.items():
            if name == "vmitrace_hdr":
                b = header_bytes()
            elif name == "vmitrace_bitmap":
                b = bitmap_bytes()
            else:
                b = bytes(rng.randrange(256) for _ in range(size))
            assert len(b) == size
            self.content[name] = b
            self.put(addr, b)
        words = struct.unpack("<8Q", self.content["vmitrace_bitmap"])
        sel = [n for n in range(512) if words[n >> 6] >> (n & 63) & 1]
        self.man = {
            "manifest_version": 1, "build_id": "test",
            "build_nonce": [f"{n:#018x}" for n in NONCE],
            "abi": {"magic": MAGIC, "version": 2, "record_size": 96,
                    "capacity": CAP, "nr_lcpu": 1},
            "expected": {"header_addr": HDR, "state_addr": STATE,
                         "records_addr": RECS, "bitmap_addr": BM},
            "ring": {"start": STATE, "end": RECS + CAP * 96,
                     "state_addr": STATE, "records_addr": RECS},
            "bitmap": {"words": [f"{w:#018x}" for w in words],
                       "syscalls": [{"nr": n, "name": str(n)} for n in sel]},
            "hash_regions": [
                {"name": n, "addr": a, "size": s,
                 "sha256": hashlib.sha256(self.content[n]).hexdigest()}
                for n, (a, s) in LAYOUT.items()],
        }
        self.man_path = os.path.join(tmp, "manifest.json")
        Path(self.man_path).write_text(json.dumps(self.man))
        self.widx = 0

    def put(self, addr, data):
        os.pwrite(self.fd, data, addr)

    def record(self, nr=3, ret=0):
        idx = self.widx
        self.put(RECS + (idx % CAP) * 96,
                 struct.pack("<QQQIHH6QqQ", idx + 1, 100, 200, nr, 0, 0,
                             5, 0, 0, 0, 0, 0, ret, 2))
        self.widx += 1
        self.put(STATE, struct.pack("<Q", self.widx))

    def set_widx(self, v):
        self.widx = v
        self.put(STATE, struct.pack("<Q", v))


class IntegrityTest(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.g = FakeGuest(self.tmp.name)
        self.hosts = set()
        self.make_checker()

    def make_checker(self, **kw):
        man = Manifest(self.g.man_path)
        regions = vi.Regions(self.g.path, self.g.man["hash_regions"],
                             dict(self.g.content))
        self.ring = GuestRing(self.g.path, man)
        self.alerts = vi.Alerter(quiet=True)
        conns = vi.ConnCounter(lambda: set(self.hosts))
        self.c = vi.Checker(man, regions, self.ring, self.alerts, conns, **kw)

    def tearDown(self):
        os.close(self.g.fd)
        self.tmp.cleanup()

    def events(self, kind=None, check=None):
        return [e for e in self.alerts.events
                if (kind is None or e["kind"] == kind)
                and (check is None or e["check"] == check)]

    def connect(self, n):
        base = len(self.hosts)
        self.hosts |= {f"0100007F:{0xC000 + base + i:04X}" for i in range(n)}

    # --- hash regions ---

    def test_clean_guest_raises_nothing(self):
        for _ in range(3):
            self.c.check_once()
        self.assertEqual(self.alerts.events, [])

    def _tamper_region(self, name, off, nbytes):
        addr, size = LAYOUT[name]
        orig = self.g.content[name]
        bad = bytes(b ^ 0xff for b in orig[off:off + nbytes])
        self.g.put(addr + off, bad)
        self.c.check_once()
        (ev,) = self.events("alert", "hash:" + name)
        d = ev["details"]
        self.assertEqual(d["first_diff_addr"], hex(addr + off))
        self.assertEqual(d["differing_bytes"], nbytes)
        self.assertEqual(d["expected"], orig[off:off + 8].hex())
        self.assertEqual(d["found"], (bad + orig[off + nbytes:])[:8].hex())
        # restore -> one "restored" event, nothing still bad
        self.g.put(addr + off, orig[off:off + nbytes])
        self.c.check_once()
        self.assertEqual(len(self.events("restored", "hash:" + name)), 1)
        self.assertEqual([k for k, v in self.alerts.state.items() if v], [])

    def test_each_region_detected_with_first_address_and_count(self):
        for name, (addr, size) in LAYOUT.items():
            with self.subTest(region=name):
                self._tamper_region(name, off=min(3, size - 3), nbytes=3)

    def test_ukplat_syscall_single_byte(self):
        # The only place the _ukplat_syscall case is exercised (decided:
        # not modified on a live guest).
        self._tamper_region("_ukplat_syscall", off=0x5a, nbytes=1)

    def test_hook_table_pointer_swap(self):
        # live test B in miniature: exittab entry := entertab entry
        enter = self.g.content["uk_syscall_entertab"]
        exit_ = self.g.content["uk_syscall_exittab"]
        diff = sum(a != b for a, b in zip(enter, exit_))
        self.g.put(LAYOUT["uk_syscall_exittab"][0], enter)
        self.c.check_once()
        (ev,) = self.events("alert", "hash:uk_syscall_exittab")
        self.assertEqual(ev["details"]["differing_bytes"], diff)

    # --- header / bitmap ---

    def test_header_nonce_mismatch(self):
        self.g.put(HDR, header_bytes(nonce=(1, 2)))
        self.c.check_once()
        (ev,) = self.events("alert", "header")
        self.assertIn("build_nonce[0]", ev["details"]["status"])
        self.assertTrue(self.events("alert", "hash:vmitrace_hdr"))
        self.g.put(HDR, header_bytes())
        self.c.check_once()
        self.assertTrue(self.events("restored", "header"))

    def test_bitmap_all_zero(self):
        # live test A in miniature
        self.g.put(BM, bytes(64))
        self.c.check_once()
        (ev,) = self.events("alert", "header")
        self.assertEqual(ev["details"]["status"], "bitmap mismatch")
        (h,) = self.events("alert", "hash:vmitrace_bitmap")
        nonzero = sum(b != 0 for b in self.g.content["vmitrace_bitmap"])
        self.assertEqual(h["details"]["differing_bytes"], nonzero)
        self.g.put(BM, self.g.content["vmitrace_bitmap"])
        self.c.check_once()
        self.assertTrue(self.events("restored", "header"))
        self.assertTrue(self.events("restored", "hash:vmitrace_bitmap"))

    # --- ring ---

    def test_write_idx_regress(self):
        for _ in range(3):
            self.g.record()
        self.c.check_once()
        self.g.set_widx(1)
        self.c.check_once()
        self.assertTrue(self.events("alert", "write_idx_regress"))

    # --- behavioural ---

    def test_stalled_when_traffic_but_no_records(self):
        self.c.check_once()                      # baseline
        for i in range(2):
            self.connect(2)
            self.c.check_once()
            if i == 0:
                self.assertFalse(self.events("alert", "stalled"))
        (ev,) = self.events("alert", "stalled")
        self.assertEqual(ev["details"]["checks"], 2)
        self.g.record(SYS_ACCEPT4, 7)            # the ring moves again
        self.c.check_once()
        self.assertTrue(self.events("restored", "stalled"))

    def test_burst_then_silence_is_stalled(self):
        # all connections in one interval, then nothing: still stalled
        # (found while writing these tests; the first version needed new
        # connections in every one of the consecutive checks)
        self.c.check_once()
        self.connect(4)
        self.c.check_once()
        self.c.check_once()
        (ev,) = self.events("alert", "stalled")
        self.assertEqual(ev["details"]["host_connections_since_ring_moved"], 4)

    def test_idle_guest_without_traffic_is_not_stalled(self):
        for _ in range(5):
            self.c.check_once()
        self.assertFalse(self.events("alert", "stalled"))

    def test_accept4_mismatch_and_recovery(self):
        self.c.check_once()                      # baseline
        self.connect(5)
        self.c.check_once()
        self.assertFalse(self.events("alert", "accept4_mismatch"))  # 1 check
        self.c.check_once()
        (ev,) = self.events("alert", "accept4_mismatch")
        self.assertEqual((ev["details"]["host_connections"],
                          ev["details"]["guest_accept4"],
                          ev["details"]["gap"]), (5, 0, 5))
        for _ in range(5):
            self.g.record(SYS_ACCEPT4, 7)
        self.c.check_once()
        self.assertTrue(self.events("restored", "accept4_mismatch"))

    def test_accept4_within_tolerance(self):
        self.c.check_once()
        self.connect(3)                          # tolerance is 3
        for _ in range(3):
            self.c.check_once()
        self.assertFalse(self.events("alert", "accept4_mismatch"))

    def test_failed_accept4_does_not_count(self):
        self.c.check_once()
        self.connect(5)
        for _ in range(5):
            self.g.record(SYS_ACCEPT4, -11)      # EAGAIN
        self.c.check_once()
        self.c.check_once()
        self.assertTrue(self.events("alert", "accept4_mismatch"))

    def test_overwrite_loss_raises_allowance(self):
        self.c.check_once()
        self.connect(6)
        for _ in range(2 * CAP):                 # 8 records lost to overwrite
            self.g.record(SYS_ACCEPT4, 7)
        self.c.check_once()
        self.c.check_once()
        self.assertFalse(self.events("alert", "accept4_mismatch"))

    def test_no_hash_mode_skips_hashes_only(self):
        self.make_checker(no_hash=True)
        self.g.put(LAYOUT["_ukplat_syscall"][0], b"\x00")
        self.c.check_once()
        self.c.check_once()
        self.assertFalse([e for e in self.alerts.events
                          if e["check"].startswith("hash:")])
        self.connect(5)
        self.c.check_once()
        self.c.check_once()
        self.assertTrue(self.events("alert", "stalled"))


class HostConnectionsTest(unittest.TestCase):
    HEADER = "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n"

    def write(self, tmp, name, rows):
        p = os.path.join(tmp, name)
        with open(p, "w") as f:
            f.write(self.HEADER)
            for i, (loc, rem, st) in enumerate(rows):
                f.write(f"   {i}: {loc} {rem} {st} 00000000:00000000 00:00000000 00000000  1000        0 1 1 0\n")
        return p

    def test_parse_both_sides_and_ipv6(self):
        with tempfile.TemporaryDirectory() as tmp:
            v4 = self.write(tmp, "tcp", [
                ("00000000:1F9A", "00000000:0000", "0A"),       # LISTEN :8090
                ("0100007F:1F9A", "0100007F:C350", "06"),       # server side, TIME_WAIT
                ("0100007F:C350", "0100007F:1F9A", "06"),       # client side
                ("0100007F:D000", "0100007F:1F90", "01"),       # :8080, other
            ])
            v6 = self.write(tmp, "tcp6", [
                ("00000000000000000000000001000000:C351",
                 "00000000000000000000000001000000:1F9A", "01"),
            ])
            keys = vi.host_connections(8090, paths=(v4, v6))
        self.assertEqual(keys, {"0100007F:C350",
                                "00000000000000000000000001000000:C351"})

    def test_counter_counts_new_keys_only(self):
        snaps = iter([{"a"}, {"a", "b"}, {"b"}, set(), {"a"}])
        c = vi.ConnCounter(lambda: next(snaps))
        news = [c.update() for _ in range(5)]
        self.assertEqual(news, [1, 1, 0, 0, 1])
        self.assertEqual(c.total, 3)


if __name__ == "__main__":
    unittest.main(verbosity=2)
