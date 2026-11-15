#!/bin/sh
# qemu-trap.sh: kraft's QEMU for images with baked traps (Phase 11-2).
# The distro qemu-system-x86_64 is run unmodified; nothing is added to the
# guest beyond what agentless/bake_traps.py put in the image.
#
#   kraft run --qemu /path/to/agentless/qemu-trap.sh -p 8080:80 --name NAME \
#       /path/to/agentless/build/net/nginx_qemu-x86_64 /usr/bin/nginx
#
# Probes (-version, -accel help, ...) and images without <kernel>.traps.json
# next to them are passed straight to QEMU. For a baked image:
#
#   1. QEMU is started paused (-S; kraftkit already passes it and resumes
#      the VM over QMP once this script has exited) and daemonized.
#   2. agentless/vmi_trap.py is started detached with --mon (this VM's HMP
#      socket) and the manifest. It starts the gdbstub, checks the code in
#      guest RAM against the image (0xCC on exactly the baked sites),
#      registers every baked site (Z0) and writes the ready file. kraftkit
#      resumes the guest (QMP cont); the stub still reports the hits.
#   3. This script exits only after the ready file appears, so the guest
#      cannot run a selected syscall before the host handles its trap. If
#      the tool fails or times out, the VM is killed and the launch fails.
#
# Environment:
#   VMITRACE_QEMU      default /usr/bin/qemu-system-x86_64
#   VMI_TRAP_OTEL      otlp (default), file or none. otlp sends spans to
#                      Jaeger (deploy/docker-compose.yml) as service
#                      vmitrace-agentless; the JSONL is written either way.
#   VMI_TRAP_OTLP_ENDPOINT  default 127.0.0.1:14317 (OTLP gRPC)
#   VMI_TRAP_ARGS      extra vmi_trap.py arguments
#   VMI_TRAP_JSONL     default logs/agentless-<qemu -name>.jsonl
#   VMI_TRAP_TIMEOUT   seconds to wait for the tool (default 20)

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
ROOT=$(dirname "$HERE")
QEMU=${VMITRACE_QEMU:-/usr/bin/qemu-system-x86_64}
PY=$ROOT/collector/.venv/bin/python
[ -x "$PY" ] || PY=python3

log() { echo "qemu-trap: $*" >&2; }

kernel= monitor= name= pidfile= paused=0 daemon=0
prev=
for a in "$@"; do
	case $prev in
	-kernel) kernel=$a ;;
	-monitor) monitor=$a ;;
	-name) name=$a ;;
	-pidfile) pidfile=$a ;;
	esac
	case $a in
	-S) paused=1 ;;
	-daemonize) daemon=1 ;;
	esac
	prev=$a
done

manifest=$kernel.traps.json
[ -n "$kernel" ] && [ -f "$manifest" ] || exec "$QEMU" "$@"

case $monitor in
unix:*) mon=${monitor#unix:}; mon=${mon%%,*} ;;
*) log "need -monitor unix:PATH (got '$monitor'); refusing"; exit 1 ;;
esac
[ "$daemon" = 1 ] || { log "need -daemonize (kraftkit passes it); refusing"; exit 1; }
[ -n "$pidfile" ] || { log "need -pidfile to stop the VM on failure; refusing"; exit 1; }

want=$("$PY" -c 'import json,sys; print(json.load(open(sys.argv[1]))["baked"]["image_sha256"])' "$manifest")
have=$(sha256sum "$kernel" | cut -d' ' -f1)
if [ "$want" != "$have" ]; then
	log "$kernel does not match $manifest (sha256 $have, want $want); refusing"
	exit 1
fi

# 1. paused, daemonized: returns once QEMU is up. With kraftkit's -S, kraftkit
# resumes the VM over QMP after this script exits (if the tool resumed it
# first, kraftkit treats the launch as failed and retries); with -S added
# here, the tool resumes it.
if [ "$paused" = 1 ]; then
	"$QEMU" "$@"
	resume=--resume-by-qemu
else
	"$QEMU" "$@" -S
	resume=
fi

kill_vm() {
	pid=$(cat "$pidfile" 2>/dev/null || true)
	[ -n "$pid" ] && kill "$pid" 2>/dev/null || true
}

# 2. the tool, detached from kraftkit
rundir=$(dirname "$mon")
ready=$rundir/vmi_trap.ready
toollog=$rundir/vmi_trap.log
rm -f "$ready"
jsonl=${VMI_TRAP_JSONL:-$ROOT/logs/agentless-${name:-vm}.jsonl}
# shellcheck disable=SC2086  # VMI_TRAP_ARGS is a word list
setsid "$PY" "$HERE/vmi_trap.py" --mon "$mon" --traps "$manifest" \
	--ready-file "$ready" $resume --jsonl "$jsonl" \
	--otel "${VMI_TRAP_OTEL:-otlp}" \
	--otlp-endpoint "${VMI_TRAP_OTLP_ENDPOINT:-127.0.0.1:14317}" \
	--otel-file "$rundir/vmi_trap.spans.jsonl" \
	--stats "$rundir/vmi_trap.stats.json" ${VMI_TRAP_ARGS:-} \
	</dev/null >>"$toollog" 2>&1 &
tool=$!

# 3. wait for every baked site to be registered
t=0
limit=$(( ${VMI_TRAP_TIMEOUT:-20} * 10 ))
while [ ! -f "$ready" ]; do
	if ! kill -0 "$tool" 2>/dev/null; then
		log "vmi_trap.py exited before arming; stopping the VM (see $toollog)"
		tail -5 "$toollog" >&2 || true
		kill_vm
		exit 1
	fi
	t=$((t + 1))
	if [ "$t" -gt "$limit" ]; then
		log "vmi_trap.py not ready after ${VMI_TRAP_TIMEOUT:-20} s; stopping the VM"
		kill "$tool" 2>/dev/null || true
		kill_vm
		exit 1
	fi
	sleep 0.1
done
log "traps registered (pid $tool, log $toollog, records $jsonl)"
