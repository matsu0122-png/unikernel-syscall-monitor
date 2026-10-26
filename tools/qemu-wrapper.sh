#!/bin/sh
# qemu-wrapper.sh: run the distro qemu-system-x86_64 with guest RAM shared as
# a file, for lib-vmitrace's host-side readers. QEMU itself is unmodified;
# only command-line options are added.
#
#   kraft run --qemu /path/to/tools/qemu-wrapper.sh -p 8080:80 --name NAME .
#
# kraftkit also calls the binary for probes (-version, -accel help); those
# are passed through untouched. For a real launch (argv contains -kernel):
#
#   1. Size = kraftkit's `-m` value ("size=64M", "64M", "64" = MiB).
#   2. Name = $VMITRACE_NAME, else kraftkit's `-name` (its machine id).
#   3. Refuse if $VMITRACE_SHM_DIR/vmitrace-<name>.mem is mapped by a running
#      process; otherwise remove the stale file (Phase 10-0 §4: it outlives
#      the VM and holds the previous guest's RAM).
#   4. Create it empty, mode 0640, group $VMITRACE_GROUP if that group
#      exists and we may chgrp to it. QEMU opens the existing file and sizes
#      it, keeping owner, group and mode.
#   5. Write vmitrace-<name>.json next to it (mem path, size, pidfile,
#      monitor socket, kernel) for the collector, same mode and group.
#   6. exec QEMU with
#        -object memory-backend-file,id=vmitrace-mem,size=S,mem-path=F,share=on
#        -machine memory-backend=vmitrace-mem
#
# Environment:
#   VMITRACE_QEMU     default /usr/bin/qemu-system-x86_64
#   VMITRACE_SHM_DIR  default /dev/shm
#   VMITRACE_GROUP    default vmitrace
#   VMITRACE_NAME     default: kraftkit's -name
#
# Security note: every member of VMITRACE_GROUP can read the *whole* guest
# RAM through this file (see README, Phase 10-2).

set -eu

QEMU=${VMITRACE_QEMU:-/usr/bin/qemu-system-x86_64}
SHM_DIR=${VMITRACE_SHM_DIR:-/dev/shm}
GROUP=${VMITRACE_GROUP:-vmitrace}

log() { echo "qemu-wrapper: $*" >&2; }

is_launch=0
mem_arg= name_arg= pidfile= monitor= kernel=
prev=
for a in "$@"; do
	case $prev in
	-kernel) is_launch=1; kernel=$a ;;
	-m) mem_arg=$a ;;
	-name) name_arg=$a ;;
	-pidfile) pidfile=$a ;;
	-monitor) monitor=$a ;;
	esac
	prev=$a
done

[ "$is_launch" = 1 ] || exec "$QEMU" "$@"

# 1. memory size in MiB
m=${mem_arg#size=}
m=${m%%,*}
case $m in
'') log "no -m in argv; refusing to guess the RAM size"; exit 1 ;;
*[0-9]M|*[0-9]m) mib=${m%?} ;;
*[0-9]G|*[0-9]g) mib=$(( ${m%?} * 1024 )) ;;
*[0-9]) mib=$m ;;
*) log "unsupported -m value '$mem_arg'"; exit 1 ;;
esac
case $mib in
''|*[!0-9]*) log "unsupported -m value '$mem_arg'"; exit 1 ;;
esac

# 2. name
name=${VMITRACE_NAME:-$name_arg}
case $name in
''|*/*|.*) log "unusable instance name '$name'"; exit 1 ;;
esac
mem=$SHM_DIR/vmitrace-$name.mem
meta=$SHM_DIR/vmitrace-$name.json

# 3. stale file, but never one a live process still maps
if [ -e "$mem" ]; then
	if grep -lqsF " $mem" /proc/[0-9]*/maps 2>/dev/null; then
		log "$mem is mapped by a running process; not touching it"
		exit 1
	fi
	rm -f "$mem"
fi
rm -f "$meta"

# 4. fresh file, 0640, group if possible
umask 027
: > "$mem"
chmod 0640 "$mem"
if getent group "$GROUP" >/dev/null 2>&1; then
	chgrp "$GROUP" "$mem" 2>/dev/null ||
		log "cannot chgrp $mem to $GROUP (is $(id -un) a member?)"
else
	log "group $GROUP does not exist; $mem stays group $(id -gn)"
fi

# 5. metadata for the collector
json_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }
{
	printf '{\n'
	printf '  "name": %s,\n' "$(json_str "$name")"
	printf '  "mem_path": %s,\n' "$(json_str "$mem")"
	printf '  "mem_size": %d,\n' $((mib * 1024 * 1024))
	printf '  "pidfile": %s,\n' "$(json_str "$pidfile")"
	printf '  "monitor": %s,\n' "$(json_str "$monitor")"
	printf '  "kernel": %s,\n' "$(json_str "$kernel")"
	printf '  "qemu": %s,\n' "$(json_str "$QEMU")"
	printf '  "wrapper_pid": %d\n' $$
	printf '}\n'
} > "$meta"
chmod 0640 "$meta"
chgrp "$GROUP" "$meta" 2>/dev/null || true

# 6. exec (no extra process). kraftkit passes -daemonize, so QEMU forks and
# the running VM's pid is the one in -pidfile, not wrapper_pid above.
exec "$QEMU" "$@" \
	-object "memory-backend-file,id=vmitrace-mem,size=${mib}M,mem-path=$mem,share=on" \
	-machine memory-backend=vmitrace-mem
