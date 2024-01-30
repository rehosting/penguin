#!/bin/bash
set -eu

# Run inside penguin container
# USAGE: ./_in_container_run.sh [kernel_version] [arch] [test_dir_name]
# Test dir is relative to the /results/ directory

KERNEL_VERSION=$1
ARCH=$2
TESTDIR=$3

# We need a "host file" for the hostfile test. Pre-position one in /tmp
cat <<EOF > /tmp/init.bin
#!/igloo/utils/sh
echo custom bin runs;
/igloo/utils/busybox ps;
EOF


# Share qcows between tests (only) if FS hashes match
ln -s /tests/qcows "/tmp/qcows"

# Directly setup a filesystem to pair with our config instead of using the standard entrypoint
# This lets us get around the fact that there's no arch to identify here and no real rootfs at all
d=$(mktemp -d)
touch "${d}/.foo"
tar --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2019-01-01' -c -C "${d}" . | gzip -n > /tmp/fs.tar.gz
md5sum /tmp/fs.tar.gz
rm -rf "$d"

# Now make us an image in /tmp/empty
fakeroot /pkg/scripts/makeImage.sh $ARCH /tmp/fs.tar.gz /tmp/empty /pkg/resources /igloo_static

# Rewrite our config template to set the specified kernel version and arch values (in arch and kernel fields)
cp /tests/$TESTDIR/config.yaml /tmp/config.yaml
sed -i -e "s/@KERNEL_VERSION@/$KERNEL_VERSION/g" -e "s/@ARCH@/$ARCH/g" /tmp/config.yaml

# If $ARCH isn't ARM we need to swap zImage for vmlinux
if [ "$ARCH" != "armel" ]; then
  sed -i "s/zImage/vmlinux/g" /tmp/config.yaml
fi

# Now render and run the config
penguin --novsock --config /tmp/config.yaml /tests/results
