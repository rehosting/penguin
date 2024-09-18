if [ ! -z "${STRACE}" ]; then
  # Strace init in the background (to follow through the exec)
  /igloo/utils/sh -c "/igloo/utils/strace -f -p 1" &
  /igloo/utils/sleep 1
  unset STRACE
fi
