# Mount sysfs, procfs, and devfs in /igloo/pfs/real
for f in sys proc dev; do
  /igloo/utils/busybox mkdir -p /igloo/pfs/real/$f
done
/igloo/utils/busybox mount -t sysfs sysfs /igloo/pfs/real/sys
/igloo/utils/busybox mount -t proc proc /igloo/pfs/real/proc
/igloo/utils/busybox mount -t devtmpfs devtmpfs /igloo/pfs/real/dev

# Make hyperfs in /igloo/pfs/fake
/igloo/utils/busybox mkdir -p /igloo/pfs/fake
/igloo/utils/busybox rm -rf /dev # Remove /dev provided by firmware
/igloo/utils/busybox ln -s /igloo/pfs/real/dev /dev # Temp /dev symlink for FUSE
/igloo/utils/hyperfs /igloo/pfs/fake -o dev,allow_other --passthrough-path=/igloo/pfs/real
/igloo/utils/busybox rm /dev

# Bind /sys,/proc,/dev to fake dirs
for f in sys proc dev; do
    /igloo/utils/busybox mkdir -p /$f
    /igloo/utils/busybox mount --bind /igloo/pfs/fake/$f /$f
done
