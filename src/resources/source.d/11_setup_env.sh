while IFS= read -r encoded_line; do
    # Decode full key=value pair
    decoded_line=$(/igloo/utils/busybox echo "$encoded_line" | /igloo/utils/busybox base64 -d)

    # Debug log before setting environment variable
    /igloo/utils/busybox echo "Restored: $decoded_line" >&2

    export "$decoded_line"
done < /proc/penguin_env