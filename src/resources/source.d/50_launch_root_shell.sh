if /igloo/utils/get_config core.root_shell > /dev/null 2>&1; then
  echo '[IGLOO INIT] Launching root shell';
  ENV=/igloo/utils/igloo_profile /igloo/utils/console &
fi
