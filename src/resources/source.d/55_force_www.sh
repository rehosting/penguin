if /igloo/utils/get_config core.force_www > /dev/null 2>&1; then
  if [ -e /igloo/utils/www_cmds ]; then
    echo '[IGLOO INIT] Force-launching webserver commands';
    /igloo/utils/sh /igloo/utils/www_cmds &
  fi
fi
