#!/igloo/utils/sh

# First, source all the scripts in /igloo/source.d
for f in /igloo/source.d/*; do
  source $f
done

# Run user-supplied scripts in /igloo/init.d
if [ -d /igloo/init.d ]; then
  for f in /igloo/init.d/*; do
    if [ -x $f ]; then
      echo "[IGLOO] user init dispatched $f"
      $f
    fi
  done
fi

if [ ! -z "${igloo_init}" ]; then
  /igloo/utils/send_hypercall readiness igloo_init "${igloo_init}" >/dev/null 2>&1 || true
  echo "[IGLOO] user init dispatched ${igloo_init}";
  # Clear the shell-coverage infrastructure marker so the firmware subtree
  # reports coverage. Penguin's boot machinery and the source.d helpers keep it
  # set (exported in preinit.sh) and stay silent.
  unset IGLOO_NO_SHELL_COV
  # Run the real guest init in a fresh UTS namespace. This marks the
  # firmware-under-analysis process subtree (which inherits the namespace) as
  # distinct from Penguin's own infrastructure, which stays in the initial
  # namespace; syscall/exec analysis loggers are scoped on that distinction. If
  # the kernel lacks CONFIG_UTS_NS, fall back to a plain exec so boot still works.
  if /igloo/utils/busybox unshare -u /igloo/utils/busybox true >/dev/null 2>&1; then
    exec /igloo/utils/busybox unshare -u "${igloo_init}"
  fi
  exec "${igloo_init}"
fi
echo "[IGLOO INIT] Fatal: no igloo_init specified in env. Abort"
exit 1
