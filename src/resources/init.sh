#!/igloo/utils/sh

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
