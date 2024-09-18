for p in /run /tmp /igloo/libnvram_tmpfs; do
  if [ ! -d $p ]; then
    # If directory doesn't exist, create it
    /igloo/utils/busybox mkdir $p
  fi
  if [ ! -n "$(/igloo/utils/busybox ls -A "$p" 2>/dev/null)" ]; then
    # If directory isn't empty, mount it as tmpfs - otherwise don't mount to ensure we don't shadow files
    /igloo/utils/busybox mount -t tmpfs tmpfs $p
  fi
done

/igloo/utils/busybox mkdir -p /dev/pts
/igloo/utils/busybox mount -t devpts devpts /dev/pts

# Populate tmpfs with hardcoded libnvram values
/igloo/utils/busybox cp /igloo/libnvram/* /igloo/libnvram_tmpfs/ || true
