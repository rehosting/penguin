# Always expose a stable /igloo/core_dumps path (a symlink into the shared
# mount) so core_pattern can reference it regardless of whether the shared
# directory feature is enabled. It dangles harmlessly when nothing is mounted.
/igloo/utils/busybox ln -sf /igloo/shared/core_dumps /igloo/core_dumps

# Bring up the shared 9p mount when either the shared-directory feature or core
# dumps are enabled -- both ride this single mount.
if [ ! -z "${SHARED_DIR}" ] || [ ! -z "${CORE_DUMPS}" ]; then
  unset SHARED_DIR
  /igloo/utils/busybox mkdir -p /igloo/shared
  echo '[IGLOO INIT] Mounting shared directory';
  # A large msize maximizes shared-dir throughput, but the per-request buffers
  # can't be allocated on memory-tight 32-bit guests (e.g. mipsel/mipseb, whose
  # limited lowmem leaves nothing for the GFP_NOFS 9p allocations -> "9pnet:
  # Couldn't grow tag array" -> ENOMEM). Fall back to a small msize so the mount
  # still succeeds there; arches that can allocate the larger buffer keep it.
  SHARED_MSIZE="${SHARED_MSIZE:-8192000}"
  /igloo/utils/busybox mount -t 9p -o trans=virtio igloo_shared_dir /igloo/shared -oversion=9p2000.L,posixacl,msize=${SHARED_MSIZE} || \
  /igloo/utils/busybox mount -t 9p -o trans=virtio igloo_shared_dir /igloo/shared -oversion=9p2000.L,posixacl,msize=131072
fi

# Set up core dumps. Independent of the shared-directory feature: dumps land in
# /igloo/shared/core_dumps via the /igloo/core_dumps symlink above.
#
# This has to come before setting up the root shell, because we want the
# `ulimit -c unlimited` to apply for programs run inside the root shell.
if [ ! -z "${CORE_DUMPS}" ]; then
  unset CORE_DUMPS
  /igloo/utils/busybox mkdir -p /igloo/shared/core_dumps
  /igloo/utils/busybox chmod -R 1777 /igloo/shared/core_dumps
  CORE_PATTERN="${CORE_DUMP_PATTERN:-/igloo/core_dumps/core_%e.%p}"
  # Make sure the underlying file is overwritten and not a hyperfs pseudofile.
  /igloo/utils/busybox echo "$CORE_PATTERN" > /proc/sys/kernel/core_pattern
  if [ ! -z "${CORE_DUMPS_LOCK}" ]; then
    unset CORE_DUMPS_LOCK
    # Lock it in: the kernel's core_pattern[] global is now populated via the
    # real handler; this hypercall asks penguin's core_pattern_guard plugin to
    # install a sysctl pseudofile that eats subsequent writes, so the guest
    # can't redirect core dumps elsewhere.
    /igloo/utils/send_hypercall core_pattern_lock "$CORE_PATTERN" >/dev/null 2>&1 || true
  fi
  # 2 = all processes dump core when possible. The core dump is owned by the current user and no security is applied. This is intended for system debugging situations only. Ptrace is unchecked. This is insecure as it allows regular users to examine the memory contents of privileged processes.
  # https://sysctl-explorer.net/fs/suid_dumpable/
  /igloo/utils/busybox echo 2 > /proc/sys/fs/suid_dumpable
  ulimit -c unlimited
fi
