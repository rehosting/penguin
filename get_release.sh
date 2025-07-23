#!/bin/bash
set -u

# Arguments
OWNER=$1
REPO=$2
VERSION=$3
ASSET_NAME=$4

#HACK: prepend `v` if to VERSION if it doesn't start with it already
VERSION="${VERSION#v}"   # Remove leading 'v' if present
VERSION="v$VERSION"      # Prepend 'v'


ACTUAL_DOWNLOAD_URL="https://github.com/${OWNER}/${REPO}/releases/download/${VERSION}/${ASSET_NAME}"

# Download the asset
curl -L -H "Accept: application/octet-stream" \
     "$ACTUAL_DOWNLOAD_URL"
