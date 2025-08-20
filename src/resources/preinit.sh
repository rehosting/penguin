#!/igloo/utils/sh
/igloo/utils/hyp_file_op get gen_live_image.sh /igloo/gen_live_image.sh
/igloo/utils/busybox /igloo/utils/busybox sh /igloo/gen_live_image.sh
if [ $? -ne 0 ]; then
    echo "[IGLOO INIT] ERROR: gen_live_image.sh failed. See /igloo/shared/host_files/live_image_guest.log for details." >&2
    exit 1
fi
exec /igloo/init