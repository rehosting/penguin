/igloo/utils/busybox mkdir -p /dev /sys /proc
/igloo/utils/busybox mount -t sysfs sysfs /sys
/igloo/utils/busybox mount -t proc proc /proc
/igloo/utils/busybox mount -t devtmpfs devtmpfs /dev
/igloo/utils/busybox insmod /igloo/shared/host_files/igloo.ko
echo '[IGLOO INIT] Mounted igloo.ko module ' $?;