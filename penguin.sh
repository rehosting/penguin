#!/bin/sh
set -eu

# This script is a wrapper for running a Python script in a Docker container.
# It supports optional flags for configuration, iteration counts, and thread counts.

# Usage examples:
# ./penguin.sh ./fw.bin /out
# ./penguin.sh --niters 5 --nthreads 2 ./fw.bin /out
# ./penguin.sh --config ./configs/myconfig /out/
# ./penguin.sh ./fws/somefw /out/

# Check minimum number of arguments
if [ "$#" -lt 2 ]; then
  echo "Usage: $0 <path to firmware file> <results directory> [--config <path to config file>] [--niters <iterations>] [--nthreads <threads>]"
  exit 1
fi

infile=""
flags=""
config=false
force=false
dev=false

# Parse command line arguments
while [ $# -gt 0 ]; do
    case "$1" in
        --config)
            config=true
            flags="$flags --config"
            shift
            infile=$(readlink -f "$1")
            shift
            ;;
        --niters|--nthreads)
            flags="$flags $1 $2"
            shift 2
            ;;
        --force)
            force=true
            shift
            ;;
        --dev)
            dev=true
            shift
            ;;
        *)
            # Break the loop if no more flags
            if [ "$1" = "--*" ]; then
                echo "Error: Unknown flag $1"
                exit 1
            else
                break
            fi
            ;;
    esac
done

# Validate and set input file if not already set by --config
if [ -z "$infile" ]; then
    infile=$(readlink -f "$1")
    shift
fi

# Validate input file
if [ ! -f "$infile" ]; then
  echo "Error: Input file $infile not found"
  exit 1
fi

# Validate output directory - we'll create this, but the parent must exist
OUT_DIR=$(readlink -f "$1")
if [ ! -d $(dirname "$OUT_DIR") ]; then
  echo "Error: Output directory $OUT_DIR cannot be created because the parent directory does not exist"
  exit 1
fi

# If output directory already exists and has a base subdirectory, bail, unless --force is set
if [ -d "${OUT_DIR}/base" ]; then
  if [ "$force" = true ]; then
    echo "Overwriting output directory ${OUT_DIR} because --force was specified."
    rm -rf "${OUT_DIR}"
  #else
  #  echo "Error: Output directory ${OUT_DIR} already contains a base subdirectory. Run with --force to overwrite."
  #  exit 1
  fi
fi
mkdir -p "${OUT_DIR}"

# Extract directory and filename for input file
IN_DIR=$(dirname "$infile")
IN_FILE=$(basename "$infile")

echo "Running penguin"
echo "    /output -> ${OUT_DIR}"
echo "    /input  -> ${IN_DIR}"

# Run the Docker command with volume mappings
if [ "$dev" = true ]; then
    # If -dev flag is set, mount the penguin soruce for development
    docker run --rm -it --privileged \
        -v "${IN_DIR}:/input" -v "${OUT_DIR}:/output" \
        -v $(pwd)/penguin/penguin:/pkg/penguin \
        --user=$(id -u):$(id -g) \
        pandare/igloo:penguin \
        python3 -m penguin $flags /input/"${IN_FILE}" /output
else
    docker run --rm -it --privileged \
        -v "${IN_DIR}:/input" -v "${OUT_DIR}:/output" \
        --user=$(id -u):$(id -g) \
        pandare/igloo:penguin \
        python3 -m penguin $flags /input/"${IN_FILE}" /output
fi