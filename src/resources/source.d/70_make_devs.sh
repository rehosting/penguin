# Two devices we want to set up properly (i.e., not as pseudofiles)
# We can't set these up as static files because /dev would get mounted
# after we populate it statically.
if [ ! -c /dev/console ]; then
  /igloo/utils/busybox mknod /dev/console c 5 1
fi
if [ ! -c /dev/ttyS0 ]; then
  # Must be arm with default /dev/ttyAMA0, let's add ttyS0 for good measure
  /igloo/utils/busybox mknod /dev/ttyS0 c 204 64
fi

if [ ! -e /dev/root ]; then
  # Symlink to root partition: /dev/vda
  /igloo/utils/busybox ln -s /dev/vda /dev/root
fi

if [ ! -e /dev/ram ]; then
  # Symlink to ramdisk
  /igloo/utils/busybox ln -s /dev/ram0 /dev/ram
fi
