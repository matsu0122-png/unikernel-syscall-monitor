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
#   3. Directory $VMITRACE_SHM_DIR (default /dev/shm/vmitrace):
#      - missing: create it 0750, chgrp $VMITRACE_GROUP; if the chgrp fails
#        (group missing, or we are not a member) remove it again and refuse.
#        /dev/shm is emptied at reboot, hence create-on-demand.
#      - present: must be a real directory (not a symlink) owned by us, mode
#        exactly 0750, group $VMITRACE_GROUP; otherwise refuse.
#   4. Refuse if <dir>/<name>.mem is mapped by a running process (only our
#      own processes are visible in /proc/*/maps, see README); otherwise
#      remove the stale file (Phase 10-0 §4: it outlives the VM and holds
#      the previous guest's RAM).
#   5. Create <name>.mem empty, 0640, group $VMITRACE_GROUP (refuse if the
#      chgrp fails). QEMU opens the existing file and sizes it, keeping
#      owner, group and mode. Write <name>.json (mem path, size, pidfile,
#      monitor socket, kernel) for the collector, same mode and group.
#   6. Start tools/vmitrace-cleanup.sh detached (setsid, stdio /dev/null,
#      same user): it waits for this QEMU to exit (pidfile + cmdline match)
#      and deletes <name>.mem / <name>.json. Without -pidfile there is
#      nothing to wait on, so no cleanup process is started.
#   7. exec QEMU with
#        -object memory-backend-file,id=vmitrace-mem,size=S,mem-path=F,share=on
#        -machine memory-backend=vmitrace-mem
#
# Environment:
#   VMITRACE_QEMU     default /usr/bin/qemu-system-x86_64
#   VMITRACE_SHM_DIR  default /dev/shm/vmitrace
#   VMITRACE_GROUP    default vmitrace (testing before the group exists:
#                     VMITRACE_GROUP=$(id -gn))
#   VMITRACE_NAME     default: kraftkit's -name
#
# Security note: every member of VMITRACE_GROUP can read the *whole* guest
# RAM through this file (see README, Phase 10-2).

set -eu

HERE=$(cd "$(dirname "$0")" && pwd)
QEMU=${VMITRACE_QEMU:-/usr/bin/qemu-system-x86_64}
SHM_DIR=${VMITRACE_SHM_DIR:-/dev/shm/vmitrace}
GROUP=${VMITRACE_GROUP:-vmitrace}

log() { echo "qemu-wrapper: $*" >&2; }

is_launch=0
mem_arg= name_arg= pidfile= monitor= kernel= netdev=
prev=
for a in "$@"; do
	case $prev in
	-kernel) is_launch=1; kernel=$a ;;
	-m) mem_arg=$a ;;
	-name) name_arg=$a ;;
	-pidfile) pidfile=$a ;;
	-monitor) monitor=$a ;;
	-netdev) netdev=$a ;;
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
mem=$SHM_DIR/$name.mem
meta=$SHM_DIR/$name.json

# 3. private directory
if [ ! -e "$SHM_DIR" ] && [ ! -L "$SHM_DIR" ]; then
	mkdir -m 0750 "$SHM_DIR"
	if ! chgrp "$GROUP" "$SHM_DIR" 2>/dev/null; then
		rmdir "$SHM_DIR"
		log "cannot give $SHM_DIR group '$GROUP' (missing group, or $(id -un) not a member); refusing"
		exit 1
	fi
	chmod 0750 "$SHM_DIR"
fi
if [ -L "$SHM_DIR" ] || [ ! -d "$SHM_DIR" ]; then
	log "$SHM_DIR is not a directory; refusing"
	exit 1
fi
st=$(stat -c '%u %a %G' "$SHM_DIR")
if [ "$st" != "$(id -u) 750 $GROUP" ]; then
	log "$SHM_DIR is '$st' (uid mode group), want '$(id -u) 750 $GROUP'; refusing"
	exit 1
fi

# 4. stale file, but never one a live process still maps
if [ -e "$mem" ]; then
	if grep -lqsF " $mem" /proc/[0-9]*/maps 2>/dev/null; then
		log "$mem is mapped by a running process; not touching it"
		exit 1
	fi
	rm -f "$mem"
fi
rm -f "$meta" "$meta.tmp"

# 5. fresh file and metadata, 0640, group $GROUP
umask 027
: > "$mem"
chmod 0640 "$mem"
if ! chgrp "$GROUP" "$mem" 2>/dev/null; then
	rm -f "$mem"
	log "cannot chgrp $mem to $GROUP; refusing"
	exit 1
fi
json_str() { printf '"%s"' "$(printf '%s' "$1" | sed 's/\\/\\\\/g; s/"/\\"/g')"; }
# written to a temporary name and renamed, so a reader never sees a
# partial file (a collector started first polls for it)
{
	printf '{\n'
	printf '  "name": %s,\n' "$(json_str "$name")"
	printf '  "mem_path": %s,\n' "$(json_str "$mem")"
	printf '  "mem_size": %d,\n' $((mib * 1024 * 1024))
	printf '  "pidfile": %s,\n' "$(json_str "$pidfile")"
	printf '  "monitor": %s,\n' "$(json_str "$monitor")"
	printf '  "kernel": %s,\n' "$(json_str "$kernel")"
	printf '  "hostfwd": %s,\n' "$(json_str "$netdev")"
	printf '  "qemu": %s,\n' "$(json_str "$QEMU")"
	printf '  "wrapper_pid": %d\n' $$
	printf '}\n'
} > "$meta.tmp"
chmod 0640 "$meta.tmp"
chgrp "$GROUP" "$meta.tmp"
mv -f "$meta.tmp" "$meta"

# 6. detached cleanup process (decision 7, revised before 10-4)
if [ -n "$pidfile" ]; then
	setsid "$HERE/vmitrace-cleanup.sh" \
		"$mem" "$(stat -c %i "$mem")" "$meta" "$(stat -c %i "$meta")" \
		"$pidfile" $$ </dev/null >/dev/null 2>&1 &
else
	log "no -pidfile in argv; $mem will not be cleaned up after exit"
fi

# 7. exec. kraftkit passes -daemonize, so QEMU forks and
# the running VM's pid is the one in -pidfile, not wrapper_pid above.
exec "$QEMU" "$@" \
	-object "memory-backend-file,id=vmitrace-mem,size=${mib}M,mem-path=$mem,share=on" \
	-machine memory-backend=vmitrace-mem
