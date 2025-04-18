
#!/igloo/utils/busybox sh

if [ ! -z "${IGLOO_EXT_MAC}" ]; then
  for iface in $(/igloo/utils/busybox ls /sys/class/net); do
      if [ "$(/igloo/utils/busybox cat /sys/class/net/$iface/address)" = "${IGLOO_EXT_MAC}" ]; then
        break
      fi
  done
  /igloo/utils/busybox ip addr add 10.0.2.15/24 dev $iface
  /igloo/utils/busybox ip route add default via 10.0.2.2
  echo "[IGLOO INIT] Found interface $iface with MAC $IGLOO_EXT_MAC and configured with IP 10.0.2.15/24"
fi
