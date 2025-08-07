#!/igloo/utils/sh

/igloo/utils/busybox mkdir /igloo/shared
echo '[IGLOO INIT] Mounting shared directory';
/igloo/utils/busybox mount -t 9p -o trans=virtio igloo_shared_dir /igloo/shared -oversion=9p2000.L,posixacl,msize=8192000
/igloo/shared/host_files/send_hypercall_raw 0xf113c0df
/igloo/utils/busybox sh /igloo/shared/host_files/gen_live_image.sh
exec /igloo/init