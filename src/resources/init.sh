#!/igloo/utils/busybox sh

/igloo/utils/busybox mkdir /igloo/shared
echo '[IGLOO INIT] Mounting shared directory';
/igloo/utils/busybox mount -t 9p -o trans=virtio igloo_shared_dir /igloo/shared -oversion=9p2000.L,posixacl,msize=8192000
# /igloo/shared/host_files/gen_live_image
/igloo/shared/host_files/send_hypercall_raw 0xf113c0df
/igloo/utils/busybox sh /igloo/shared/host_files/gen_live_image.sh

# First, source all the scripts in /igloo/source.d
for f in /igloo/source.d/*; do
  source $f
done

# Run user-supplied scripts in /igloo/init.d
if [ -d /igloo/init.d ]; then
  for f in /igloo/init.d/*; do
    if [ -x $f ]; then
      echo "[IGLOO INIT] Running $f"
      $f
    fi
  done
fi

if [ ! -z "${igloo_init}" ]; then
  echo '[IGLOO INIT] Running specified init binary';
  exec "${igloo_init}"
fi
echo "[IGLOO INIT] Fatal: no igloo_init specified in env. Abort"
exit 1
