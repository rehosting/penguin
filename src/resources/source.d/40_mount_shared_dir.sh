if [ ! -z "${SHARED_DIR}" ]; then
  unset SHARED_DIR
  /igloo/utils/busybox mkdir /igloo/shared
  echo '[IGLOO INIT] Mounting shared directory';
  /igloo/utils/busybox mount -t 9p -o trans=virtio igloo_shared_dir /igloo/shared -oversion=9p2000.L

  # Set up core dumps
  #
  # This has to come before setting up the root shell,
  # because we want the `ulimit -c unlimited` to apply for programs run inside the root shell.
  /igloo/utils/busybox mkdir -p /igloo/shared/core_dumps
  # Make sure the underlying file is overwritten and not a hyperfs pseudofile at that path.
  # One might want to make `/proc/sys/kernel/core_pattern` a pseudofile to prevent the guest from overwriting it.
  /igloo/utils/busybox echo '/igloo/shared/core_dumps/core_%e.%p' > /igloo/pfs/real/proc/sys/kernel/core_pattern
  ulimit -c unlimited
fi
