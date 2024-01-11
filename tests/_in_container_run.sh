#!/bin/bash
set -eu

# Run inside penguin container
# USAGE: ./_in_container_run.sh [arch] [test_dir_name]
# Test dir is relative to the /results/ directory

ARCH=$1
TESTDIR=$2
# Optional 3rd arg, default is 20
NITERS=${3:-20}

# Make sure any files we create are world-rwx
umask 000

# DEBUG: extract a local copy of penguin_plugins for testing
#mkdir /tmp/plugins
#tar xf /tests/penguin_plugins.tar.gz -C /tmp/plugins
#cp "/tmp/plugins/$ARCH/panda"* "/usr/local/lib/panda/$ARCH/"

# Share qcows between test (only if config FS hashes match)
# XXX: Is arch a part of that hash?
ln -s /tests/qcows "/tmp/qcows"

# Directly setup a filesystem to pair with our config instead of using the standard entrypoint
# This lets us get around the fact that there's no arch to identify here and no real rootfs at all
d=$(mktemp -d)
touch "${d}/.foo"
tar czf /tmp/fs.tar.gz -C "${d}" .
rm -rf "$d"

# Now make us an image in /tmp/empty
fakeroot /pkg/scripts/makeImage.sh $ARCH /tmp/fs.tar.gz /tmp/empty /pkg/resources /igloo_static >/dev/null

# Rewrite our config template to set the specified arch value (in arch and kernel fields)
cp /tests/$TESTDIR/config.yaml /tmp/config.yaml
sed -i "s/ARCH/$ARCH/g" /tmp/config.yaml

# If $ARCH isn't ARM we need to swap zImage for vmlinux
if [ "$ARCH" != "armel" ]; then
  sed -i "s/zImage/vmlinux/g" /tmp/config.yaml
fi

# Now render and run the config
penguin --novsock --config /tmp/config.yaml --niters $NITERS --singlecore /tests/results
