#!/bin/bash
set -eu

# Run inside penguin container
# USAGE: ./_in_container_run.sh [test_dir_name]
# Test dir is relative to the /results/ directory

TESTDIR=$1
ARCH=$2

RESULTS="${TESTDIR}/output"

# We need a "host file" for the hostfile test. Pre-position one in /tmp/hostfile
mkdir /tmp/hostfile
cat <<EOF > /tmp/hostfile/init.bin
#!/igloo/utils/sh
echo custom bin runs;
/igloo/utils/busybox touch /tmp/success
EOF

# Share qcows between tests (only) if FS hashes match
ln -s /tests/qcows "/tmp/qcows"

# Make a consistent shared directory which goes into results
ln -s $RESULTS/ /results

# Directly setup a filesystem to pair with our config instead of using the standard entrypoint
# This lets us get around the fact that there's no arch to identify here and no real rootfs at all
d=$(mktemp -d)
touch "${d}/.foo"
tar --sort=name --owner=root:0 --group=root:0 --mtime='UTC 2019-01-01' -c -C "${d}" . | \
  gzip -n > /tmp/fs.tar.gz
rm -rf "$d"

# Now make us an image in /tmp/generated
TARBALL="/tmp/fs.tar.gz"
REPACK_DIR="/tmp/generated"
RESOURCE_DIR="/pkg/resources"
STATIC_DIR="/igloo_static"

WORK_DIR="${REPACK_DIR}/work"
TARFILE="${REPACK_DIR}/fs.tar"
IGLOO="${WORK_DIR}/igloo"

# Validate and prepare tarball
if [ ! -e "$TARBALL" ]; then
    echo "Error: Cannot find tarball of root filesystem in $REPACK_DIR" >&2
    exit 1
fi

# Create required directories
mkdir -p "$WORK_DIR" "$IGLOO/utils" "$IGLOO/keys"

# Extract fs.tar.gz -> work/fs.tar
gunzip -c "$TARBALL" > "$TARFILE"

# Populate work/* with the files we want to add in work/fd/ and work/igloo/
# Copy keys and utilities
cp "$RESOURCE_DIR/static_keys/"* "$IGLOO/keys"
for t in "console" "libnvram" "utils.bin" "utils.source" "vpn"; do
    UTILS="$STATIC_DIR/$t"
    [ -d "$UTILS" ] || { echo "FATAL: Missing utilities directory $UTILS" >&2; exit 1; }

    for f in "$UTILS"/*.${ARCH} "$UTILS"/*.all; do
        [ -e "$f" ] || { continue; }
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

fakeroot /pkg/scripts/makeImage.sh "${REPACK_DIR}/fs.tar.gz" /tmp/generated
mkdir -p $RESULTS $TESTDIR
chmod -R 777 $RESULTS $TESTDIR
penguin --config $TESTDIR/config.yaml $RESULTS || (echo "Test failed"; chmod -R 777 $RESULTS; exit 1)
chmod -R 777 $RESULTS $TESTDIR