if /igloo/utils/get_config core.strace > /dev/null 2>&1; then
  # Strace init in the background (to follow through the exec)
  /igloo/utils/sh -c "/igloo/utils/strace -f -p 1" &
  /igloo/utils/sleep 1
fi
