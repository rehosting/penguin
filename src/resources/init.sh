#!/igloo/utils/sh

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
/igloo/utils/hyperfs /igloo/pfs/fake -o dev,allow_other --passthrough-path=/igloo/pfs/real --hyperfile-paths="$IGLOO_HYPERFILE_PATHS"
/igloo/utils/busybox rm /dev

# Bind /sys,/proc,/dev to fake dirs
for f in sys proc dev; do
    /igloo/utils/busybox mkdir -p /$f
    /igloo/utils/busybox mount --bind /igloo/pfs/fake/$f /$f
done

for p in /run /tmp /igloo/libnvram_tmpfs; do
  /igloo/utils/busybox mkdir $p
  /igloo/utils/busybox mount -t tmpfs tmpfs $p
done

/igloo/utils/busybox mkdir -p /dev/pts
/igloo/utils/busybox mount -t devpts devpts /dev/pts

# Populate tmpfs with hardcoded libnvram values
/igloo/utils/busybox cp /igloo/libnvram/* /igloo/libnvram_tmpfs/ || true

if [ -e /igloo/utils/random_seed ]; then
  /igloo/utils/busybox cat /igloo/utils/random_seed > /dev/random
  /igloo/utils/busybox cat /igloo/utils/random_seed > /dev/urandom
fi

if [ ! -z "${ROOT_SHELL}" ]; then
  echo '[IGLOO INIT] Launching root shell';
  LD_PRELOAD=/igloo/lib_inject.so ENV=/igloo/utils/igloo_profile /igloo/utils/console &
  unset ROOT_SHELL
fi

if [ ! -z "${SHARED_DIR}" ]; then
  /igloo/utils/busybox mkdir /igloo/shared
  echo '[IGLOO INIT] Mounting shared directory';
  /igloo/utils/busybox mount -t 9p -o trans=virtio igloo_shared_dir /igloo/shared -oversion=9p2000.L
  unset SHARED_DIR
fi

if [ ! -z "${WWW}" ]; then
  if [ -e /igloo/utils/www_cmds ]; then
    echo '[IGLOO INIT] Force-launching webserver commands';
    LD_PRELOAD=/igloo/lib_inject.so /igloo/utils/sh /igloo/utils/www_cmds &
  fi
  unset WWW
fi

if [ ! -z "${CID}" ]; then
  echo '[IGLOO INIT] Launching VPN';
  /igloo/utils/vpn guest -c ${CID} >/dev/null &
  unset CID
fi

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

# Pretend we have some network interfaces. Note these aren't
# connected to anything. Pseudofile penguin_net is populated
# from config's netdevs list.
for iface in $(/igloo/utils/busybox cat /proc/penguin_net); do
  /igloo/utils/busybox ip link add $iface type dummy
  /igloo/utils/busybox ip link set $iface up
done
  /igloo/utils/busybox ip link delete dummy0 || true


## Add a bridge with eth0 and assign it an IP
#/igloo/utils/busybox brctl addbr br0
#/igloo/utils/busybox ifconfig br0 192.168.1.1
#/igloo/utils/busybox brctl addif br0 eth0
#/igloo/utils/busybox ifconfig eth0 0.0.0.0 up
#
## Add a second bridge with eth1 and assign it an IP
#/igloo/utils/busybox brctl addbr br1
#/igloo/utils/busybox ifconfig br1 10.0.1.1
#/igloo/utils/busybox brctl addif br1 eth1
#/igloo/utils/busybox ifconfig eth1 0.0.0.0 up
#
#ip addr add 18.1.1.1/24 dev eth0 # External IP
#ip addr add 192.168.1.2/24 dev eth1 # Internal IP

if [ ! -z "${STRACE}" ]; then
  # Strace init in the background (to follow through the exec)
  /igloo/utils/sh -c "/igloo/utils/strace -f -p 1" &
  /igloo/utils/sleep 1
  unset STRACE
fi


if [ ! -z "${igloo_init}" ]; then
  echo '[IGLOO INIT] Running specified init binary';
  LD_PRELOAD=/igloo/lib_inject.so exec "${igloo_init}"
fi
echo "[IGLOO INIT] Fatal: no igloo_init specified in env. Abort"
exit 1