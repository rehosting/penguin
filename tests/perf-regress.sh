#!/usr/bin/env sh

if ! [ -d /pkg/penguin ]; then
    # Outside container
    # Download, convert, and run firmware
    mnt=$(mktemp -d)
    echo "MNT: $mnt"
    trap 'rm -rf -- "$mnt"' EXIT
    curl -o $mnt/fw.bin \
        https://downloads.openwrt.org/releases/18.06.1/targets/ar71xx/generic/openwrt-18.06.1-ar71xx-generic-ubnt-unifi-outdoor-squashfs-sysupgrade.bin
    docker run --rm -t \
        -v "$mnt":/host \
        ghcr.io/rehosting/fw2tar:main \
        fakeroot python3 /fw2tar.py /host/fw.bin
    docker run --rm -t \
        -v "$mnt":/fw \
        -v "$(pwd)":/tests \
        rehosting/penguin \
        /tests/perf-regress.sh
    exit $?
fi

# In container
set -eu
trap 'rm -rf /fw/*' EXIT
penguin /fw/fw.rootfs.tar.gz /fw/results

# Start emulation
penguin --config /fw/results/config.yaml /fw/results/out &
penguin_pid=$!

# Wait for HTTP server to start
while true; do
    httpd_netbind="$(grep 'uhttpd,4,tcp' /fw/results/out/netbinds.csv 2> /dev/null || true)"
    ! [ -z "$httpd_netbind" ] && break
    sleep 1
done

# Kill penguin and get boot time
kill $penguin_pid
boot_time="$(echo "$httpd_netbind" | sed 's/uhttpd,4,tcp,0.0.0.0,80,//')"
boot_time="$(printf '%.f' "$boot_time")"
cat /fw/results/out/pseudofiles_failures.yaml
echo "BOOTED IN $boot_time SECONDS"
