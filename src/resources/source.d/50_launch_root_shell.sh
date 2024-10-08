if [ ! -z "${ROOT_SHELL}" ]; then
  echo '[IGLOO INIT] Launching root shell';
  ENV=/igloo/utils/igloo_profile /igloo/utils/console &
  unset ROOT_SHELL
fi
