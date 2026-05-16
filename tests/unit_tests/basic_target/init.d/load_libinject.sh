#!/igloo/utils/sh
# Force lib_inject.so to load by invoking a dynamic /igloo/utils binary with
# LD_PRELOAD set. The constructor inside lib_inject.d/dropin_lib.c then writes
# its marker file. We don't care about the binary's exit status.
LD_PRELOAD=/igloo/dylibs/lib_inject.so /igloo/utils/test_nvram get __unused_libinject_loader__ >/dev/null 2>&1 || /busybox true
