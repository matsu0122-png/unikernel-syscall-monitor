"""Shared helper: launch/stop a `gdb -x monitor.py` capture session as a
subprocess, attached to an already-running gdbstub port.

Used by both run_capture.py (fixed-duration capture) and bench_overhead.py
(capture running for the duration of a benchmark run).
"""
import subprocess
import sys
import threading
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
DBG_KERNEL = HERE.parent / ".unikraft/build/nginx_qemu-x86_64.dbg"


def _stream_to_stdout(proc: subprocess.Popen, buf: list) -> None:
    """Runs in a background thread: relays the child's stdout to our own
    stdout line-by-line as it arrives (instead of only being visible once
    read in bulk at the end), while also buffering it for the final
    return value expected by callers."""
    for line in iter(proc.stdout.readline, ""):
        buf.append(line)
        sys.stdout.write(line)
        sys.stdout.flush()


def _popen_gdb(gdb_cmd: list, env: dict) -> subprocess.Popen:
    proc = subprocess.Popen(
        gdb_cmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True, env=env
    )
    proc._captured_lines = []
    proc._stream_thread = threading.Thread(
        target=_stream_to_stdout, args=(proc, proc._captured_lines), daemon=True
    )
    proc._stream_thread.start()
    return proc


def launch_gdb_capture(port: int, env: dict) -> subprocess.Popen:
    gdb_cmd = [
        # stdbuf forces gdb's own stdio to line-buffer even though it's
        # writing to a pipe (not a tty) -- otherwise gdb's libc may fully
        # buffer output, delaying it until the buffer fills or the process
        # exits, which would defeat the live streaming below.
        "stdbuf", "-oL", "-eL",
        "gdb", "-q", "-nx",
        "-ex", f"file {DBG_KERNEL}",
        "-ex", f"target remote 127.0.0.1:{port}",
        "-x", str(HERE / "monitor.py"),
        # monitor.py only arms the breakpoint -- it no longer calls
        # gdb.execute("continue") itself (see its docstring), so we do it
        # here as the final -ex in the sequence.
        "-ex", "continue",
    ]
    return _popen_gdb(gdb_cmd, env)


def launch_gdb_preloaded(env: dict) -> subprocess.Popen:
    """Start gdb with the debug symbols loaded and the syscall breakpoint
    pre-armed (as a *pending* breakpoint -- no target is attached yet), so
    that all that's left once a gdbstub appears is `target remote` +
    `continue` via attach_preloaded_gdb() below.

    This exists for run_capture_from_boot.py: kraftkit launches QEMU with
    `-S` (paused at boot) and only resumes it itself, over its own QMP
    connection, ~90-100ms after the monitor socket appears (confirmed
    empirically). Loading symbols (~70ms for this build's 22M .dbg file)
    and resolving/arming the breakpoint eats most of that window, so doing
    both ahead of time -- while `kraft run` is still building/booting --
    leaves only the fast part (a local TCP connect + continue) to race
    against kraftkit's auto-resume.
    """
    gdb_cmd = ["stdbuf", "-oL", "-eL", "gdb", "-q", "-nx", "-ex", f"file {DBG_KERNEL}"]
    proc = _popen_gdb(gdb_cmd, env)
    # monitor.py only needs the symbol table (just loaded above), not a
    # live target -- gdb resolves *_ukplat_syscall and arms a pending
    # breakpoint that activates the instant a target attaches.
    proc.stdin.write(f"source {HERE / 'monitor.py'}\n")
    proc.stdin.flush()
    return proc


def attach_preloaded_gdb(proc: subprocess.Popen, port: int) -> None:
    """Hand a gdbstub listening on `port` to a gdb process previously
    started with launch_gdb_preloaded(), and resume the guest."""
    proc.stdin.write(f"target remote 127.0.0.1:{port}\n")
    proc.stdin.write("continue\n")
    proc.stdin.flush()


def drain_gdb_output(proc: subprocess.Popen) -> str:
    """Wait for the streaming thread to hit EOF (i.e. the process's stdout
    closed) and return everything it relayed, for callers that also want
    the full text at the end (e.g. to log it)."""
    proc._stream_thread.join(timeout=5)
    return "".join(proc._captured_lines)


def stop_gdb_capture(proc: subprocess.Popen) -> str:
    """SIGINT (breaks the guest out of `continue`) -> `detach`/`quit` over
    stdin -> fall back to terminate() if it doesn't exit cleanly. Returns
    whatever gdb printed, for logging."""
    import signal

    if proc.poll() is None:
        proc.send_signal(signal.SIGINT)
        # Give gdb time to actually land back at the (gdb) prompt before
        # sending more commands -- sending "detach" too soon after SIGINT
        # (observed with a 0.5s pause) can race gdb's own "target running"
        # state and produce a harmless but noisy
        # "Cannot execute this command while the target is running" error.
        # Pacing the two commands out fixes this in practice.
        time.sleep(1.0)
        try:
            proc.stdin.write("detach\n")
            proc.stdin.flush()
            time.sleep(0.5)
            proc.stdin.write("quit\ny\n")
            proc.stdin.flush()
        except (BrokenPipeError, OSError):
            pass
        try:
            proc.wait(timeout=5)
        except subprocess.TimeoutExpired:
            proc.terminate()
            proc.wait(timeout=5)
    return drain_gdb_output(proc)
