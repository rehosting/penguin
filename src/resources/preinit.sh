#!/igloo/boot/sh
# When analysis scoping is enabled, gen_image.py injects an
# `export IGLOO_NO_SHELL_COV=1` line right below this comment. It marks this
# process (and everything it spawns) as Penguin infrastructure so the busybox
# shell-coverage instrumentation stays silent; the marker is inherited across
# fork/exec through init.sh and the source.d helpers, and init.sh clears it at
# the handoff into the firmware init so only the firmware is covered. With
# core.analysis_scope: none the line is omitted and all shells report.
/igloo/boot/busybox insmod /igloo/boot/igloo.ko
/igloo/boot/hyp_file_op get gen_live_image.sh /igloo/boot/gen_live_image.sh
/igloo/boot/busybox sh /igloo/boot/gen_live_image.sh
if [ $? -ne 0 ]; then
    echo "[IGLOO INIT] ERROR: gen_live_image.sh failed. See /igloo/shared/host_files/live_image_guest.log for details." >&2
    exit 1
fi
exec /igloo/init