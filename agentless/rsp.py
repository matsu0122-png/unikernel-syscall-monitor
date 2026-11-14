"""Minimal GDB Remote Serial Protocol client for QEMU's gdbstub (Phase 11).

Only what selective trapping needs: no-ack mode, Z0/z0 (software
breakpoints: QEMU writes 0xCC into guest RAM and sets
KVM_GUESTDBG_USE_SW_BP), g (registers), m (memory), P (one register),
c / s, Ctrl-C, D.

All-stop: while the guest runs, the stub accepts nothing but Ctrl-C, so
every command except interrupt() must be sent while the guest is stopped.
interrupt() may be called from another thread; the reader is the one
thread blocked in wait_stop().
"""

import socket
import struct
import threading

# QEMU x86_64 register numbers (target.xml order)
RAX, RBX, RCX, RDX, RSI, RDI, RBP, RSP = range(8)
R8, R9, R10, R11, R12, R13, R14, R15 = range(8, 16)
RIP = 16


class RspError(Exception):
    pass


class Rsp:
    def __init__(self, host, port, timeout=None):
        self.sock = socket.create_connection((host, port), timeout=10)
        self.sock.settimeout(timeout)
        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
        self.buf = bytearray()
        self.ack = True
        self.send_lock = threading.Lock()
        self.round_trips = 0

    # -- framing -----------------------------------------------------------
    def _send(self, payload: bytes):
        cs = sum(payload) & 0xFF
        with self.send_lock:
            self.sock.sendall(b"$" + payload + b"#%02x" % cs)

    def _fill(self):
        chunk = self.sock.recv(65536)
        if not chunk:
            raise EOFError("gdbstub closed the connection (QEMU gone?)")
        self.buf.extend(chunk)

    def _recv_packet(self) -> bytes:
        while True:
            while self.buf[:1] in (b"+", b"-"):
                del self.buf[0]
            start = self.buf.find(b"$")
            if start >= 0:
                end = self.buf.find(b"#", start)
                if end >= 0 and len(self.buf) >= end + 3:
                    payload = bytes(self.buf[start + 1:end])
                    del self.buf[:end + 3]
                    if self.ack:
                        with self.send_lock:
                            self.sock.sendall(b"+")
                    return self._unescape(payload)
            self._fill()

    @staticmethod
    def _unescape(p: bytes) -> bytes:
        if b"}" not in p and b"*" not in p:
            return p
        out = bytearray()
        i = 0
        while i < len(p):
            c = p[i]
            if c == 0x7D:                      # '}' escape
                out.append(p[i + 1] ^ 0x20)
                i += 2
            elif c == 0x2A:                    # '*' run length
                out.extend(out[-1:] * (p[i + 1] - 29))
                i += 2
            else:
                out.append(c)
                i += 1
        return bytes(out)

    def cmd(self, payload: str) -> str:
        self._send(payload.encode())
        self.round_trips += 1
        return self._recv_packet().decode()

    def ok(self, payload: str):
        r = self.cmd(payload)
        if r != "OK":
            raise RspError(f"{payload!r} -> {r!r}")

    # -- session -----------------------------------------------------------
    def start(self):
        """Return the stop reason. QEMU stops a running guest when a debugger
        connects and sends that stop (T02) unasked; read it first, or every
        later reply is taken for the previous command's. QEMU 6.2 answers
        QStartNoAckMode with "" (unsupported): acks stay on then."""
        timeout = self.sock.gettimeout()
        self.sock.settimeout(1.0)
        try:
            first = self._recv_packet().decode()
        except socket.timeout:
            first = None
        self.sock.settimeout(timeout)
        if self.cmd("QStartNoAckMode") == "OK":
            self.ack = False
        # QEMU refuses P (write one register) with "" until the client has
        # read target.xml (gdb_has_xml).
        self.cmd("qSupported:xmlRegisters=i386")
        off = 0
        while True:
            r = self.cmd(f"qXfer:features:read:target.xml:{off:x},800")
            if not r or r[0] not in "lm":
                raise RspError(f"qXfer target.xml: {r[:40]!r}")
            off += len(r) - 1
            if r[0] == "l":
                break
        return first or self.cmd("?")

    def regs(self):
        """rax..r15, rip as 17 ints (from one `g`)."""
        h = self.cmd("g")
        if len(h) < 17 * 16:
            raise RspError(f"short g reply ({len(h)} chars)")
        return struct.unpack("<17Q", bytes.fromhex(h[:17 * 16]))

    def read(self, addr, n) -> bytes:
        h = self.cmd(f"m{addr:x},{n:x}")
        if h.startswith("E"):
            raise RspError(f"m {addr:#x},{n}: {h}")
        return bytes.fromhex(h)

    def write(self, addr, data: bytes):
        self.ok(f"M{addr:x},{len(data):x}:{data.hex()}")

    def set_reg(self, regno, value):
        self.ok(f"P{regno:x}={struct.pack('<Q', value).hex()}")

    def insert(self, addr):
        self.ok(f"Z0,{addr:x},1")

    def remove(self, addr):
        self.ok(f"z0,{addr:x},1")

    def cont(self):
        self._send(b"c")
        self.round_trips += 1

    def step(self) -> str:
        self._send(b"s")
        self.round_trips += 1
        return self._recv_packet().decode()

    def wait_stop(self) -> str:
        return self._recv_packet().decode()

    def interrupt(self):
        with self.send_lock:
            self.sock.sendall(b"\x03")

    def detach(self):
        try:
            self.cmd("D")
        finally:
            self.sock.close()


def stop_signal(reply: str):
    """'T05thread:01;' / 'S05' -> 5; 'W..'/'X..' (exited) -> None."""
    if reply[:1] in ("T", "S"):
        return int(reply[1:3], 16)
    return None
