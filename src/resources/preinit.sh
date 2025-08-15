#!/igloo/utils/sh

/igloo/utils/busybox mkdir /igloo/shared
echo '[IGLOO INIT] Mounting shared directory';
/igloo/utils/busybox mount -t 9p -o trans=virtio igloo_shared_dir /igloo/shared -oversion=9p2000.L,posixacl,msize=8192000
/igloo/shared/host_files/send_hypercall_raw 0xf113c0df
/igloo/utils/busybox sh /igloo/shared/host_files/gen_live_image.sh > /igloo/shared/host_files/live_image_guest.log 2>&1
if [ $? -ne 0 ]; then
    echo "[IGLOO INIT] ERROR: gen_live_image.sh failed. See /igloo/shared/host_files/live_image_guest.log for details." >&2
    exit 1
fi
/igloo/shared/host_files/send_hypercall_raw 0xf113c1df
exec /igloo/init