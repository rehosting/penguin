#!/igloo/utils/sh

# First, source all the scripts in /igloo/source.d
for f in /igloo/source.d/*; do
  source $f
done

# Run user-supplied scripts in /igloo/init.d
if [ -d /igloo/init.d ]; then
  for f in /igloo/init.d/*; do
    if [ -x $f ]; then
      echo "[IGLOO] user init dispatched $f"
      $f
    fi
  done
fi

if [ ! -z "${igloo_init}" ]; then
  /igloo/utils/send_hypercall readiness igloo_init "${igloo_init}" >/dev/null 2>&1 || true
  echo "[IGLOO] user init dispatched ${igloo_init}";
  exec "${igloo_init}"
fi
echo "[IGLOO INIT] Fatal: no igloo_init specified in env. Abort"
exit 1
