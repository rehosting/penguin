if [ ! -z "${WWW}" ]; then
  if [ -e /igloo/utils/www_cmds ]; then
    echo '[IGLOO INIT] Force-launching webserver commands';
    /igloo/utils/sh /igloo/utils/www_cmds &
  fi
  unset WWW
fi
