# Bring up the loopback interface
/igloo/utils/busybox ip link set lo up

# Pretend we have some network interfaces. Note these aren't
# connected to anything. Pseudofile penguin_net is populated
# from config's netdevs list.
for iface in $(/igloo/utils/busybox cat /proc/penguin_net 2>/dev/null || echo ""); do
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
