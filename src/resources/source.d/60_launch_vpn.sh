if [ ! -z "${CID}" ]; then
  echo '[IGLOO INIT] Launching VPN';
  # Owned-interface datapaths: when IGLOO_OWN_IFACES is set (by the vpn pyplugin
  # from plugins.vpn.interfaces), the guest agent stands up a tap-backed userspace
  # TCP/IP stack per interface so forwards routed to it genuinely ingress there and
  # traverse the firmware's netfilter INPUT chain. Taps are created here (before
  # firmware rc configures the interface), so wan_ifname=<NAME> finds it.
  # IGLOO_OWN_IFACES = "NAME:HOST/GUEST/PREFIX;NAME2:..." (semicolon-separated).
  IFACE_FLAGS=""
  if [ ! -z "${IGLOO_OWN_IFACES}" ]; then
    OLDIFS="${IFS}"; IFS=';'
    for spec in ${IGLOO_OWN_IFACES}; do
      [ -z "${spec}" ] && continue
      IFACE_FLAGS="${IFACE_FLAGS} --own-iface ${spec}"
    done
    IFS="${OLDIFS}"
    echo "[IGLOO INIT] VPN owning interfaces: ${IGLOO_OWN_IFACES}";
  elif [ ! -z "${IGLOO_WAN_IFACE}" ]; then
    # Deprecated single-interface alias (kept for one release).
    echo "[IGLOO INIT] VPN WAN datapath enabled on ${IGLOO_WAN_IFACE} (deprecated; use plugins.vpn.interfaces)";
    IFACE_FLAGS="--wan-iface ${IGLOO_WAN_IFACE}"
  fi

  if [ ! -z "${IFACE_FLAGS}" ]; then
    RUST_LOG=info /igloo/utils/vpn guest -c ${CID} ${IFACE_FLAGS} 2>&1 &
  else
    /igloo/utils/vpn guest -c ${CID} >/dev/null &
  fi
  unset CID
fi
