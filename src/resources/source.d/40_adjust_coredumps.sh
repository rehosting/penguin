
# Set up core dumps
#
# This has to come before setting up the root shell,
# because we want the `ulimit -c unlimited` to apply for programs run inside the root shell.
/igloo/utils/busybox mkdir -p /igloo/shared/core_dumps
/igloo/utils/busybox chmod -R 1777 /igloo/shared/core_dumps
# Make sure the underlying file is overwritten and not a hyperfs pseudofile at that path.
# One might want to make `/proc/sys/kernel/core_pattern` a pseudofile to prevent the guest from overwriting it.
/igloo/utils/busybox echo '/igloo/shared/core_dumps/core_%e.%p' > /igloo/pfs/real/proc/sys/kernel/core_pattern
# 2 all processes dump core when possible. The core dump is owned by the current user and no security is applied. This is intended for system debugging situations only. Ptrace is unchecked. This is insecure as it allows regular users to examine the memory contents of privileged processes.
# https://sysctl-explorer.net/fs/suid_dumpable/
/igloo/utils/busybox echo 2 > /igloo/pfs/real/proc/sys/fs/suid_dumpable
ulimit -c unlimited