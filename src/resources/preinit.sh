#!/igloo/boot/sh
/igloo/boot/busybox insmod /igloo/boot/igloo.ko
/igloo/boot/hyp_file_op get gen_live_image.sh /igloo/boot/gen_live_image.sh
/igloo/boot/busybox sh /igloo/boot/gen_live_image.sh
if [ $? -ne 0 ]; then
    echo "[IGLOO INIT] ERROR: gen_live_image.sh failed. See /igloo/shared/host_files/live_image_guest.log for details." >&2
    exit 1
fi
exec /igloo/init