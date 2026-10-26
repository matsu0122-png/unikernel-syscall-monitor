#!/bin/sh
# vmitrace-cleanup.sh: started by qemu-wrapper.sh (setsid, stdio on
# /dev/null, same user as QEMU) right before it execs QEMU. Waits for that
# QEMU to exit, then deletes the shared guest-RAM file and its .json, which
# would otherwise outlive the VM (Phase 10-0 §4). The directory stays 0750:
# only its owner (the QEMU user) can delete files in it, so this runs as
# that user rather than in the collector.
#
#   vmitrace-cleanup.sh MEM MEM_INODE META META_INODE PIDFILE WRAPPER_PID
#
# - QEMU is identified by the pid in PIDFILE *and* by MEM appearing in its
#   /proc/<pid>/cmdline, so a reused pid is not mistaken for it.
# - If QEMU never shows up (start failed): once WRAPPER_PID (which became
#   QEMU's pre-daemonize process) is gone and no matching pid appeared
#   within GRACE seconds, clean up anyway.
# - Only files with the inodes the wrapper created are removed, so a later
#   instance that reused the name keeps its files.

set -u
mem=$1 mem_ino=$2 meta=$3 meta_ino=$4 pidfile=$5 wrapper_pid=$6
GRACE=${VMITRACE_CLEANUP_GRACE:-10}
START_TIMEOUT=${VMITRACE_CLEANUP_START_TIMEOUT:-300}

say() { command -v logger >/dev/null 2>&1 && logger -t vmitrace-cleanup "$*"; }

is_qemu() {
	[ -n "$1" ] && [ -r "/proc/$1/cmdline" ] &&
		tr '\0' '\n' < "/proc/$1/cmdline" 2>/dev/null | grep -qF "mem-path=$mem,"
}

remove_if_ours() {
	f=$1 ino=$2
	[ -e "$f" ] || return 0
	if [ "$(stat -c %i "$f" 2>/dev/null)" = "$ino" ]; then
		rm -f "$f" && say "removed $f"
	else
		say "not removing $f: inode changed (reused name)"
	fi
}

pid=
waited=0 wrapper_gone_at=
while :; do
	p=$(cat "$pidfile" 2>/dev/null) || p=
	if is_qemu "$p"; then
		pid=$p
		break
	fi
	if ! kill -0 "$wrapper_pid" 2>/dev/null; then
		[ -n "$wrapper_gone_at" ] || wrapper_gone_at=$waited
		if [ $((waited - wrapper_gone_at)) -ge "$GRACE" ]; then
			say "QEMU for $mem never appeared; cleaning up"
			break
		fi
	fi
	if [ "$waited" -ge "$START_TIMEOUT" ]; then
		say "gave up waiting for QEMU for $mem; leaving files"
		exit 1
	fi
	sleep 1
	waited=$((waited + 1))
done

if [ -n "$pid" ]; then
	while is_qemu "$pid"; do
		sleep 1
	done
fi

remove_if_ours "$mem" "$mem_ino"
remove_if_ours "$meta" "$meta_ino"
