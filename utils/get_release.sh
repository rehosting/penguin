#!/bin/bash
set -u

# Arguments
OWNER=$1
REPO=$2
VERSION=$3
GITHUB_TOKEN=$4

# Fetch the download URL of the first asset in the release using curl
ASSET_API_URL=$(curl -sL \
                  -H "Accept: application/vnd.github+json" \
                  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                  -H "X-GitHub-Api-Version: 2022-11-28" \
                  "https://api.github.com/repos/${OWNER}/${REPO}/releases/tags/v${VERSION}" | jq -r '.assets[0].url')

if [ -z "$ASSET_API_URL" ]; then
    echo "Asset API URL not found in https://api.github.com/repos/${OWNER}/${REPO}/releases/tags/v${VERSION}" >&2
    exit 1
fi

# Download the artifact using curl, handling the redirect
TEMP_REDIRECT=$(mktemp)
curl -s -L -I -o $TEMP_REDIRECT \
     -H "Authorization: Bearer ${GITHUB_TOKEN}" \
     -H "Accept: application/octet-stream" \
     "$ASSET_API_URL"

# Parse the temporary file for the Location header (the actual asset URL)
ACTUAL_DOWNLOAD_URL=$(grep -i ^Location: $TEMP_REDIRECT | tail -1 | cut -d' ' -f2 | tr -d '\r')

# Clean up the temporary file
rm $TEMP_REDIRECT

# Download the asset
curl -L -H "Accept: application/octet-stream" \
     "$ACTUAL_DOWNLOAD_URL"