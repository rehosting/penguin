if [ -e /igloo/utils/random_seed ]; then
  /igloo/utils/busybox cat /igloo/utils/random_seed > /dev/random
  /igloo/utils/busybox cat /igloo/utils/random_seed > /dev/urandom
fi
