if [ ! -z "${SHARED_DIR}" ]; then
  unset SHARED_DIR
  /igloo/utils/busybox mkdir /igloo/shared
  echo '[IGLOO INIT] Mounting shared directory';
  # A large msize maximizes shared-dir throughput, but the per-request buffers
  # can't be allocated on memory-tight 32-bit guests (e.g. mipsel/mipseb, whose
  # limited lowmem leaves nothing for the GFP_NOFS 9p allocations -> "9pnet:
  # Couldn't grow tag array" -> ENOMEM). Fall back to a small msize so the mount
  # still succeeds there; arches that can allocate 8MB keep the larger buffer.
  /igloo/utils/busybox mount -t 9p -o trans=virtio igloo_shared_dir /igloo/shared -oversion=9p2000.L,posixacl,msize=8192000 || \
  /igloo/utils/busybox mount -t 9p -o trans=virtio igloo_shared_dir /igloo/shared -oversion=9p2000.L,posixacl,msize=131072

  # Set up core dumps
  #
  # This has to come before setting up the root shell,
  # because we want the `ulimit -c unlimited` to apply for programs run inside the root shell.
  /igloo/utils/busybox mkdir -p /igloo/shared/core_dumps
  /igloo/utils/busybox chmod -R 1777 /igloo/shared/core_dumps
  # Make sure the underlying file is overwritten and not a hyperfs pseudofile at that path.
  CORE_PATTERN='/igloo/shared/core_dumps/core_%e.%p'
  /igloo/utils/busybox echo "$CORE_PATTERN" > /proc/sys/kernel/core_pattern
  # Lock it in: the kernel's core_pattern[] global is now populated via the real
  # handler; this hypercall asks penguin's core_pattern_guard plugin to install a
  # sysctl pseudofile that eats subsequent writes, so the guest can't redirect
  # core dumps elsewhere.
  /igloo/utils/send_hypercall core_pattern_lock "$CORE_PATTERN" >/dev/null 2>&1 || true
  # 2 all processes dump core when possible. The core dump is owned by the current user and no security is applied. This is intended for system debugging situations only. Ptrace is unchecked. This is insecure as it allows regular users to examine the memory contents of privileged processes.
  # https://sysctl-explorer.net/fs/suid_dumpable/
  /igloo/utils/busybox echo 2 > /proc/sys/fs/suid_dumpable
  ulimit -c unlimited
fi
