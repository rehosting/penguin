#!/bin/bash

set -euo pipefail
trap 'echo "An unexpected error occurred." >&2; exit 1' ERR

# Usage information
usage() {
    echo "Usage: $0 <fs.tar.gz> </artifact/base>"
    exit 1
}

# Check for the correct number of arguments
[ "$#" -eq 2 ] || usage

TARBALL="$1"
ARTIFACTS="$2"

QCOW="${ARTIFACTS}/image.qcow"

mkdir -p "${ARTIFACTS}"

# 1GB of padding. XXX is this a good amount - does it slow things down if it's too much?
# Our disk images are sparse, so this doesn't actually take up any space?
PADDING_MB=1024
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

# Decompress the archive and store in artifacts/fs.tar
gunzip -c "$TARBALL" > "${ARTIFACTS}/fs.tar"

# Calculate image and filesystem size
UNPACKED_SIZE=$(zcat "$TARBALL" | wc -c)
UNPACKED_SIZE=$(( UNPACKED_SIZE + 1024 * 1024 * PADDING_MB ))
REQUIRED_BLOCKS=$(( (UNPACKED_SIZE + BLOCK_SIZE - 1) / BLOCK_SIZE + 1024 ))
FILESYSTEM_SIZE=$(( REQUIRED_BLOCKS * BLOCK_SIZE ))

# Calculate the number of inodes - err on the side of too big since we'll add more to the FS later
INODE_SIZE=8192  # For every 8KB of disk space, we'll allocate an inode
NUMBER_OF_INODES=$(( FILESYSTEM_SIZE / INODE_SIZE ))
NUMBER_OF_INODES=$(( NUMBER_OF_INODES + 1000 )) # Padding for more files getting added later
# Make tempfile
WORK_DIR=$(mktemp -d)
IMAGE="$WORK_DIR/image.raw"
echo "Creating raw Image $IMAGE with size $FILESYSTEM_SIZE"
truncate -s "$FILESYSTEM_SIZE" "$IMAGE"
genext2fs --faketime  -N "$NUMBER_OF_INODES" -b "$REQUIRED_BLOCKS" -B $BLOCK_SIZE -a "$TARBALL" "$IMAGE" 2>&1 | grep -v "bad type 'x'"

# Now convert the image to qcow2 format and clean up
echo "Converting image to QCOW2 format"
qemu-img convert -f raw -O qcow2 "$IMAGE" "$QCOW"
md5sum "$QCOW"
rm -rf "$IMAGE" "$WORK_DIR"
