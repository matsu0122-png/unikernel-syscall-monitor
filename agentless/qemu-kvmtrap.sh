#!/bin/sh
# qemu-kvmtrap.sh: kraft's QEMU for images with baked traps, handled inside
# the QEMU process by agentless/kvmtrap/libvmitrap.so (Phase 11-3).
#
#   kraft run --qemu /path/to/agentless/qemu-kvmtrap.sh -p 8080:80 --name NAME \
#       /path/to/agentless/build/net/nginx_qemu-x86_64 /usr/bin/nginx
#
# The QEMU binary is the distro one, unmodified; libvmitrap.so is preloaded
# into it and acts only at the KVM ioctl boundary (see libvmitrap.c). No gdbstub,
# no VM stop per trap. Probes and images without <kernel>.traps.json are
# passed straight to QEMU without the library.
#
#   1. agentless/kvmtrap/kvmtrap.py writes the conf and the reference bytes
#      into the instance's runtime dir, creates the record ring and starts
#      reading it (detached; it ends when QEMU exits).
#   2. QEMU starts with LD_PRELOAD=libvmitrap.so. kraftkit passes -S and
#      resumes it over QMP once this script has exited; the library enables
#      software breakpoints on each vCPU before its first KVM_RUN.
#
# Environment (same names as qemu-trap.sh, so bench_baked.py works with both):
#   VMITRACE_QEMU      default /usr/bin/qemu-system-x86_64
#   VMI_TRAP_OTEL      otlp (default), file or none
#   VMI_TRAP_OTLP_ENDPOINT  default 127.0.0.1:14317
#   VMI_TRAP_ARGS      extra kvmtrap.py arguments (--no-ret, --stats, ...)
#   VMI_TRAP_JSONL     default logs/kvmtrap-<qemu -name>.jsonl
#   VMI_TRAP_TIMEOUT   seconds to wait for kvmtrap.py (default 20)

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
QEMU=${VMITRACE_QEMU:-/usr/bin/qemu-system-x86_64}
LIB=$HERE/kvmtrap/libvmitrap.so
PY=$ROOT/collector/.venv/bin/python
[ -x "$PY" ] || PY=python3

log() { echo "qemu-kvmtrap: $*" >&2; }

kernel= monitor= name= pidfile=
prev=
for a in "$@"; do
	case $prev in
	-kernel) kernel=$a ;;
	-monitor) monitor=$a ;;
	-name) name=$a ;;
	-pidfile) pidfile=$a ;;
	esac
	prev=$a
done

manifest=$kernel.traps.json
[ -n "$kernel" ] && [ -f "$manifest" ] || exec "$QEMU" "$@"

[ -f "$LIB" ] || { log "$LIB not built (make -C $HERE/kvmtrap); refusing"; exit 1; }
case $monitor in
unix:*) mon=${monitor#unix:}; mon=${mon%%,*} ;;
*) log "need -monitor unix:PATH (got '$monitor'); refusing"; exit 1 ;;
esac
[ -n "$pidfile" ] || { log "need -pidfile; refusing"; exit 1; }
[ -n "$name" ] || { log "need -name; refusing"; exit 1; }

want=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["baked"]["image_sha256"])' "$manifest")
have=$(sha256sum "$kernel" | cut -d' ' -f1)
if [ "$want" != "$have" ]; then
	log "$kernel does not match $manifest (sha256 $have, want $want); refusing"
	exit 1
fi

rundir=$(dirname "$mon")
ready=$rundir/kvmtrap.ready
toollog=$rundir/kvmtrap.reader.log
rm -f "$ready" "$pidfile"
jsonl=${VMI_TRAP_JSONL:-$ROOT/logs/kvmtrap-$name.jsonl}

# 1. conf, ref, ring; the reader stays detached from kraftkit
# shellcheck disable=SC2086  # VMI_TRAP_ARGS is a word list
setsid "$PY" "$HERE/kvmtrap/kvmtrap.py" --traps "$manifest" --rundir "$rundir" \
	--name "$name" --ready-file "$ready" --pidfile "$pidfile" --jsonl "$jsonl" \
	--otel "${VMI_TRAP_OTEL:-otlp}" \
	--otlp-endpoint "${VMI_TRAP_OTLP_ENDPOINT:-127.0.0.1:14317}" \
	--otel-file "$rundir/kvmtrap.spans.jsonl" \
	--stats "$rundir/kvmtrap.stats.json" ${VMI_TRAP_ARGS:-} \
	</dev/null >>"$toollog" 2>&1 &
tool=$!

t=0
limit=$(( ${VMI_TRAP_TIMEOUT:-20} * 10 ))
while [ ! -f "$ready" ]; do
	if ! kill -0 "$tool" 2>/dev/null; then
		log "kvmtrap.py exited before the conf was ready (see $toollog)"
		tail -5 "$toollog" >&2 || true
		exit 1
	fi
	t=$((t + 1))
	if [ "$t" -gt "$limit" ]; then
		log "kvmtrap.py not ready after ${VMI_TRAP_TIMEOUT:-20} s"
		kill "$tool" 2>/dev/null || true
		exit 1
	fi
	sleep 0.1
done

# 2. QEMU with the library; it exits non-zero if the conf cannot be loaded
if ! LD_PRELOAD=$LIB VMI_KVMTRAP_CONF=$rundir/kvmtrap.conf "$QEMU" "$@"; then
	log "QEMU with libvmitrap.so failed to start (see $rundir/kvmtrap.log)"
	kill "$tool" 2>/dev/null || true
	exit 1
fi
log "QEMU started with libvmitrap.so (reader pid $tool, log $rundir/kvmtrap.log, records $jsonl)"
