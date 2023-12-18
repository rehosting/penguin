#!/bin/bash

set -euo pipefail
trap 'echo "An unexpected error occurred." >&2; exit 1' ERR

# Usage information
usage() {
    echo "Usage: $0 <architecture> <extract_dir> <igloo_dir> <static_dir>"
    exit 1
}

# Check for the correct number of arguments
[ "$#" -eq 4 ] || usage

ARCH="$1"
REPACK_DIR="$2"
IGLOO_DIR="$3"
STATIC_DIR="$4"

WORK_DIR="${REPACK_DIR}/work"
IMAGE="${REPACK_DIR}/image.raw"
QCOW="${REPACK_DIR}/image.qcow"
TARBALL="${REPACK_DIR}/fs.tar.gz"
TARFILE="${REPACK_DIR}/fs.tar"
FD="${WORK_DIR}/firmadyne"
IGLOO="${WORK_DIR}/igloo"
BLOCK_SIZE=4096

# Helper function to calculate image size
calculate_image_size() {
    local tarball_size=$(tar -tf "$1" --totals 2>&1 | tail -1 | cut -f4 -d' ')
    local minimum_image_size=$((tarball_size + 10 * 1024 * 1024))
    local image_size=8388608
    while [ $image_size -le $minimum_image_size ]; do
        image_size=$((image_size * 2))
    done
    echo $image_size
}

# Validate and prepare tarball
if [ ! -e "$TARBALL" ]; then
    echo "Error: Cannot find tarball of root filesystem in $REPACK_DIR" >&2
    exit 1
fi
gunzip -c "$TARBALL" > "$TARFILE"

# Create required directories
mkdir -p "$FD/libnvram" "$FD/libnvram.override" "$IGLOO/utils" "$IGLOO/keys"

# Copy keys and utilities
cp "$IGLOO_DIR/resources/static_keys/"* "$IGLOO/keys"

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

# Validate and append to the tarball
[ -e "$TARFILE" ] || { echo "Error: Tar file $TARFILE does not exist" >&2; exit 1; }
[ -s "$TARFILE" ] || { echo "Error: Tar file $TARFILE is empty" >&2; exit 1; }
tar --append --owner=root --group=root -f "$TARFILE" -C "$WORK_DIR" .

# Calculate image and filesystem size
IMAGE_SIZE=$(calculate_image_size "$TARFILE")
UNPACKED_SIZE=$(tar -xf "$TARFILE" -C "$WORK_DIR" --totals 2>&1 | tail -1 | cut -f4 -d' ')
REQUIRED_BLOCKS=$(( (UNPACKED_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE + 1024 ))
FILESYSTEM_SIZE=$(( REQUIRED_BLOCKS * BLOCK_SIZE ))

# Create and populate the image
echo "Creating QEMU Image $IMAGE with size $FILESYSTEM_SIZE"
truncate -s "$FILESYSTEM_SIZE" "$IMAGE"
genext2fs -b "$REQUIRED_BLOCKS" -B $BLOCK_SIZE -a "$TARFILE" "$IMAGE" 2>&1 | grep -v "bad type 'x'"

# Now convert the image to qcow2 format
echo "Converting image to QCOW2 format"
qemu-img convert -f raw -O qcow2 "$IMAGE" "$QCOW"
rm -f "$IMAGE"