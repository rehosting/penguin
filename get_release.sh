#!/bin/bash
set -u

# Arguments
OWNER=$1
REPO=$2
VERSION=$3
ASSET_NAME=$4

ACTUAL_DOWNLOAD_URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"

# Download the asset
curl -L -H "Accept: application/octet-stream" \
     "$ACTUAL_DOWNLOAD_URL"
