if [ /igloo/utils/get_config --bool core.force_www ]; then
  if [ -e /igloo/utils/www_cmds ]; then
    echo '[IGLOO INIT] Force-launching webserver commands';
    /igloo/utils/sh /igloo/utils/www_cmds &
  fi
  unset WWW
fi
