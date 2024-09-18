if [ ! -z "${CID}" ]; then
  echo '[IGLOO INIT] Launching VPN';
  /igloo/utils/vpn guest -c ${CID} >/dev/null &
  unset CID
fi
