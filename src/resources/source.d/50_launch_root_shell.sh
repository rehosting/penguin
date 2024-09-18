if [ ! -z "${ROOT_SHELL}" ]; then
  echo '[IGLOO INIT] Launching root shell';
  LD_PRELOAD=lib_inject.so ENV=/igloo/utils/igloo_profile /igloo/utils/console &
  unset ROOT_SHELL
fi
