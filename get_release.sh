#!/bin/bash
set -ux

# Arguments
OUTPUT_FILE=$1
OWNER=$2
REPO=$3
VERSION=$4
GITHUB_TOKEN=$5
ASSET_NAME=""
if [ $# -ge 6 ]; then
    ASSET_NAME="$6"
fi

# Default CURL_OPTIONS if not set
: "${CURL_OPTIONS:=--retry 5 --retry-delay 5 --max-time 600}"

# Special case for GitHub auto-generated source tarballs
if [ "$ASSET_NAME" = "source.tar.gz" ]; then
    # Try to get tarball_url from the release API (works for private repos/releases)
    RELEASE_JSON=$(curl -sfL \
                  -H "Accept: application/vnd.github+json" \
                  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                  -H "X-GitHub-Api-Version: 2022-11-28" \
                  "https://api.github.com/repos/${OWNER}/${REPO}/releases/tags/${VERSION}" 2>/dev/null)
    TAR_URL=$(echo "$RELEASE_JSON" | jq -r '.tarball_url // empty')
    if [ -n "$TAR_URL" ] && [ "$TAR_URL" != "null" ]; then
        if [ "$OUTPUT_FILE" = "-" ]; then
            curl $CURL_OPTIONS -fL -H "Authorization: Bearer ${GITHUB_TOKEN}" -o - "$TAR_URL" || \
            curl $CURL_OPTIONS -fL -o - "$TAR_URL" || {
                echo "ERROR: Failed to download source tarball for owner='${OWNER}', repo='${REPO}', tag='${VERSION}' (tarball_url)." >&2
                exit 10
            }
        else
            curl $CURL_OPTIONS -fL -H "Authorization: Bearer ${GITHUB_TOKEN}" -o "$OUTPUT_FILE" "$TAR_URL" || \
            curl $CURL_OPTIONS -fL -o "$OUTPUT_FILE" "$TAR_URL" || {
                echo "ERROR: Failed to download source tarball for owner='${OWNER}', repo='${REPO}', tag='${VERSION}' (tarball_url)." >&2
                exit 10
            }
        fi
        exit $?
    fi
    # Fallback to public URL if tarball_url is not available
    if [ "$OUTPUT_FILE" = "-" ]; then
        curl $CURL_OPTIONS -fL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
            "https://github.com/${OWNER}/${REPO}/archive/refs/tags/${VERSION}.tar.gz" || \
        curl $CURL_OPTIONS -fL \
            "https://github.com/${OWNER}/${REPO}/archive/refs/tags/${VERSION}.tar.gz" || {
            echo "ERROR: Failed to download source tarball for owner='${OWNER}', repo='${REPO}', tag='${VERSION}'." >&2
            exit 10
        }
    else
        curl $CURL_OPTIONS -fL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
            -o "$OUTPUT_FILE" \
            "https://github.com/${OWNER}/${REPO}/archive/refs/tags/${VERSION}.tar.gz" || \
        curl $CURL_OPTIONS -fL \
            -o "$OUTPUT_FILE" \
            "https://github.com/${OWNER}/${REPO}/archive/refs/tags/${VERSION}.tar.gz" || {
            echo "ERROR: Failed to download source tarball for owner='${OWNER}', repo='${REPO}', tag='${VERSION}'." >&2
            exit 10
        }
    fi
    exit $?
fi
if [ "$ASSET_NAME" = "source.zip" ]; then
    if [ "$OUTPUT_FILE" = "-" ]; then
        curl $CURL_OPTIONS -fL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
            "https://github.com/${OWNER}/${REPO}/archive/refs/tags/${VERSION}.zip" || {
            echo "ERROR: Failed to download source zip for owner='${OWNER}', repo='${REPO}', tag='${VERSION}'." >&2
            exit 11
        }
    else
        curl $CURL_OPTIONS -fL -H "Authorization: Bearer ${GITHUB_TOKEN}" \
            -o "$OUTPUT_FILE" \
            "https://github.com/${OWNER}/${REPO}/archive/refs/tags/${VERSION}.zip" || {
            echo "ERROR: Failed to download source zip for owner='${OWNER}', repo='${REPO}', tag='${VERSION}'." >&2
            exit 11
        }
    fi
    exit $?
fi

# Fetch the release info using curl
RELEASE_JSON=$(curl -sfL \
                  -H "Accept: application/vnd.github+json" \
                  -H "Authorization: Bearer ${GITHUB_TOKEN}" \
                  -H "X-GitHub-Api-Version: 2022-11-28" \
                  "https://api.github.com/repos/${OWNER}/${REPO}/releases/tags/${VERSION}" 2>/dev/null)
CURL_STATUS=$?
if [ $CURL_STATUS -ne 0 ]; then
    echo "ERROR: Network or authentication error when contacting GitHub API (curl exit code $CURL_STATUS)." >&2
    exit 12
fi

# Check for API rate limiting
if echo "$RELEASE_JSON" | grep -q 'API rate limit exceeded'; then
    RESET_TIME=$(curl -sI -H "Authorization: Bearer ${GITHUB_TOKEN}" https://api.github.com/rate_limit | grep -i '^x-ratelimit-reset:' | awk '{print $2}' | tr -d '\r')
    if [ -n "$RESET_TIME" ]; then
        RESET_DATE=$(date -d @${RESET_TIME} 2>/dev/null || date -r ${RESET_TIME} 2>/dev/null)
        echo "GitHub API rate limit exceeded. Limit resets at: $RESET_DATE ($RESET_TIME)" >&2
    else
        echo "GitHub API rate limit exceeded." >&2
    fi
    exit 2
fi

# Check for invalid authentication
if echo "$RELEASE_JSON" | grep -q 'Bad credentials'; then
    echo "ERROR: Invalid GitHub token or insufficient permissions for owner='${OWNER}', repo='${REPO}'." >&2
    exit 13
fi

# Check for missing release
if echo "$RELEASE_JSON" | grep -q '"message": "Not Found"'; then
    echo "ERROR: GitHub release not found for owner='${OWNER}', repo='${REPO}', tag='${VERSION}'." >&2
    exit 3
fi

# Check for malformed JSON or missing assets array
if ! echo "$RELEASE_JSON" | jq -e '.assets' >/dev/null 2>&1; then
    echo "ERROR: Malformed or unexpected GitHub API response for owner='${OWNER}', repo='${REPO}', tag='${VERSION}'." >&2
    exit 14
fi

if [ -n "$ASSET_NAME" ]; then
    ASSET_API_URL=$(echo "$RELEASE_JSON" | jq -r --arg NAME "$ASSET_NAME" '.assets[]? | select(.name == $NAME) | .url')
else
    ASSET_API_URL=$(echo "$RELEASE_JSON" | jq -r '.assets[0]?.url')
fi

if [ -z "$ASSET_API_URL" ] || [ "$ASSET_API_URL" = "null" ]; then
    if [ -n "$ASSET_NAME" ]; then
        echo "ERROR: Asset '$ASSET_NAME' not found in release for owner='${OWNER}', repo='${REPO}', tag='${VERSION}'." >&2
    else
        echo "ERROR: No assets found in release for owner='${OWNER}', repo='${REPO}', tag='${VERSION}'." >&2
    fi
    exit 4
fi

# Download the artifact using curl, handling the redirect
TEMP_REDIRECT=$(mktemp)
curl -sfL -I -o $TEMP_REDIRECT \
     -H "Authorization: Bearer ${GITHUB_TOKEN}" \
     -H "Accept: application/octet-stream" \
     "$ASSET_API_URL" || \
curl -sfL -I -o $TEMP_REDIRECT \
     -H "Accept: application/octet-stream" \
     "$ASSET_API_URL" || {
    echo "ERROR: Failed to fetch asset redirect for '$ASSET_NAME' from GitHub." >&2
    rm -f $TEMP_REDIRECT
    exit 15
}

# Parse the temporary file for the Location header (the actual asset URL)
ACTUAL_DOWNLOAD_URL=$(grep -i ^Location: $TEMP_REDIRECT | tail -1 | cut -d' ' -f2 | tr -d '\r')

# Clean up the temporary file
rm $TEMP_REDIRECT

if [ -z "$ACTUAL_DOWNLOAD_URL" ]; then
    echo "ERROR: Could not resolve download URL for asset '$ASSET_NAME'." >&2
    exit 16
fi

# Download the asset
if [ "$OUTPUT_FILE" = "-" ]; then
    curl $CURL_OPTIONS -fL -H "Accept: application/octet-stream" \
         "$ACTUAL_DOWNLOAD_URL" || \
    curl $CURL_OPTIONS -fL "$ACTUAL_DOWNLOAD_URL" || {
        echo "ERROR: Failed to download asset from '$ACTUAL_DOWNLOAD_URL'." >&2
        exit 17
    }
else
    curl $CURL_OPTIONS -fL -H "Accept: application/octet-stream" \
         -o "$OUTPUT_FILE" \
         "$ACTUAL_DOWNLOAD_URL" || \
    curl $CURL_OPTIONS -fL -o "$OUTPUT_FILE" "$ACTUAL_DOWNLOAD_URL" || {
        echo "ERROR: Failed to download asset from '$ACTUAL_DOWNLOAD_URL'." >&2
        exit 17
    }
fi