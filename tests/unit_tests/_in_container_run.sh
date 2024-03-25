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
TARBALL="/tmp/fs.tar.gz"
REPACK_DIR="/tmp/empty"
RESOURCE_DIR="/pkg/resources"
STATIC_DIR="/igloo_static"

WORK_DIR="${REPACK_DIR}/work"
TARFILE="${REPACK_DIR}/fs.tar"
FD="${WORK_DIR}/firmadyne"
IGLOO="${WORK_DIR}/igloo"

# Validate and prepare tarball
if [ ! -e "$TARBALL" ]; then
    echo "Error: Cannot find tarball of root filesystem in $REPACK_DIR" >&2
    exit 1
fi

# Create required directories
mkdir -p "$WORK_DIR" "$FD" "$IGLOO/utils" "$IGLOO/keys"
mkdir -p /tmp/artifacts

# Extract fs.tar.gz -> work/fs.tar
gunzip -c "$TARBALL" > "$TARFILE"

# Populate work/* with the files we want to add in work/fd/ and work/igloo/
# Copy keys and utilities
cp "$RESOURCE_DIR/static_keys/"* "$IGLOO/keys"
for t in "console" "libnvram" "utils.bin" "utils.source" "vpn"; do
    UTILS="$STATIC_DIR/$t"
    [ -d "$UTILS" ] || { echo "FATAL: Missing utilities directory $UTILS" >&2; exit 1; }

    for f in "$UTILS"/*.${ARCH} "$UTILS"/*.all; do
        [ -e "$f" ] || { echo "WARN: No files matching pattern $f"; continue; }
        fname=$(basename "$f")
        dest="${IGLOO}/utils/${fname%.*}"
        cp "$f" "$dest"
        chmod +x "$dest"
    done
done

# Create symbolic links
ln -s "/igloo/utils/busybox" "$IGLOO/utils/sh"
ln -s "/igloo/utils/busybox" "$IGLOO/utils/sleep"

# Validate and append this data to our tar file
[ -e "$TARFILE" ] || { echo "Error: Tar file $TARFILE does not exist" >&2; exit 1; }
[ -s "$TARFILE" ] || { echo "Error: Tar file $TARFILE is empty" >&2; exit 1; }
tar --append --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2019-01-01' -f "$TARFILE" -C "$WORK_DIR" .
gzip "$TARFILE"

fakeroot /pkg/scripts/makeImage.sh "${REPACK_DIR}/fs.tar.gz" /tmp/empty


# Rewrite our config template to set the specified kernel version and arch values (in arch and kernel fields)
cp /tests/$TESTDIR/config.yaml /tmp/config.yaml
sed -i -e "s/@KERNEL_VERSION@/$KERNEL_VERSION/g" -e "s/@ARCH@/$ARCH/g" /tmp/config.yaml

# If $ARCH isn't ARM we need to swap zImage for vmlinux
if [ "$ARCH" != "armel" ]; then
  sed -i "s/zImage/vmlinux/g" /tmp/config.yaml
fi

# Now render and run the config
penguin --novsock --config /tmp/config.yaml /tests/results

# QEMU inside Docker makes the shared dir only readable by root.
# There are fmode and dmode options for virtfs but PANDA doesn't support them.
if [ -d /tests/results/shared ]; then
  chmod -R 777 /tests/results/shared
fi
