#!/usr/bin/env python3
"""One-shot host-side helper: attach QEMU's gdbstub to an already-running
`kraft run -d` instance via its monitor socket.

Usage:
    python3 attach_gdbstub.py <instance-name> [--port PORT]

Prints the chosen TCP port on success so callers can pipe it into
`gdb -ex "target remote localhost:<port>"`.

Design notes (see /home/matsu/.claude/plans/moonlit-kindling-dragon.md):
- We resolve the instance's mon.sock via `kraft ps -l -o json` at call
  time (never cache/hardcode a path -- stale sockets from dead instances
  are left behind on disk and must not be reused).
- IMPORTANT: kraftkit's mon.sock is plain QEMU HMP (the human-readable
  text monitor, "(qemu) " prompt), NOT QMP/JSON -- verified empirically
  (connecting shows a "QEMU 6.2.0 monitor" banner, and it echoes input
  character-by-character with terminal escape codes as a readline TTY
  would). So we speak plain HMP text, not JSON.
- We issue `gdbserver tcp::<port>` as an HMP command. Per QEMU's
  hmp_gdbserver, this starts a gdbstub listener on a live, running guest
  without pausing it (no -s/-S needed at boot time).
"""
import argparse
import json
import re
import socket
import subprocess
import sys
from pathlib import Path

KRAFTKIT_RUNTIME_DIR = Path.home() / ".local/share/kraftkit/runtime"
PROMPT = b"(qemu) "
ANSI_ESCAPE_RE = re.compile(rb"\x1b\[[0-9;]*[A-Za-z]")


def find_instance_runtime_dir(name: str) -> Path:
    out = subprocess.run(
        ["kraft", "ps", "-l", "-o", "json"], capture_output=True, text=True, check=True
    )
    # `kraft ps -o json` prints literal `null` (not `[]`) when nothing is running.
    instances = json.loads(out.stdout) or []
    for inst in instances:
        if inst.get("name") == name:
            instance_id = inst.get("machine_id")
            if not instance_id:
                raise RuntimeError(f"instance {name!r} found but has no machine_id field: {inst}")
            return KRAFTKIT_RUNTIME_DIR / instance_id
    raise RuntimeError(f"no running kraft instance named {name!r} (kraft ps -l -o json: {instances})")


def _recv_until_prompt(sock: socket.socket, timeout: float = 3.0) -> bytes:
    sock.settimeout(timeout)
    buf = bytearray()
    while not buf.endswith(PROMPT):
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("HMP monitor socket closed unexpectedly")
        buf.extend(chunk)
    return bytes(buf)


def hmp_command(sock: socket.socket, cmdline: str) -> str:
    """Send one HMP command and return its de-escaped, echo-stripped reply text."""
    sock.sendall(cmdline.encode() + b"\n")
    raw = _recv_until_prompt(sock)
    # Strip ANSI cursor-movement escapes from the readline echo, then drop
    # the echoed command line itself -- the real reply is everything after
    # the first \r\n.
    cleaned = ANSI_ESCAPE_RE.sub(b"", raw)
    _, _, rest = cleaned.partition(b"\r\n")
    reply = rest[: -len(PROMPT)] if rest.endswith(PROMPT) else rest
    return reply.decode(errors="replace").strip()


def find_free_port(start: int = 1234) -> int:
    for port in range(start, start + 100):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            try:
                s.bind(("127.0.0.1", port))
                return port
            except OSError:
                continue
    raise RuntimeError(f"no free TCP port found in range {start}-{start + 99}")


def attach_gdbserver(mon_sock_path: Path, port: int) -> str:
    if not mon_sock_path.exists():
        raise RuntimeError(f"mon.sock not found at {mon_sock_path}")

    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.connect(str(mon_sock_path))
    try:
        _recv_until_prompt(sock)  # discard the initial banner + first prompt
        # Bind loopback-only (tcp:127.0.0.1:PORT), not tcp::PORT (which binds
        # 0.0.0.0) -- verified empirically that `tcp::PORT` exposes the
        # gdbstub (full memory/register read-write) on all interfaces, which
        # is an unnecessary exposure on a host that already publishes other
        # ports (e.g. -p 8080:80).
        reply = hmp_command(sock, f"gdbserver tcp:127.0.0.1:{port}")
        if "could not open gdbserver" in reply.lower() or "error" in reply.lower():
            raise RuntimeError(f"gdbserver HMP command reported failure: {reply!r}")
        if not reply:
            raise RuntimeError("gdbserver HMP command returned an empty reply (unexpected)")
        return reply
    finally:
        sock.close()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("name", help="kraft instance name (as passed to --name)")
    parser.add_argument("--port", type=int, default=None, help="TCP port for gdbstub (default: probe free port from 1234)")
    args = parser.parse_args()

    runtime_dir = find_instance_runtime_dir(args.name)
    mon_sock = runtime_dir / "mon.sock"
    port = args.port if args.port is not None else find_free_port()

    hmp_text = attach_gdbserver(mon_sock, port)
    print(f"gdbstub attached: {hmp_text.strip()}")
    print(f"PORT={port}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
