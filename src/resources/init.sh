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
  # Scrub penguin's internal env before handing off, so the firmware-under-
  # analysis (and its children) don't inherit tooling-only values:
  #   * IGLOO_NO_SHELL_COV -- shell-coverage infrastructure marker (exported in
  #     preinit.sh, NOT in the boot env blob); clearing it lets the firmware
  #     subtree report coverage while Penguin's boot machinery stays silent.
  #   * The boot env blob (/igloo/boot/igloo_env.sh) -- scrubbing from the blob
  #     keeps this in lockstep with boot_env's partition rule and picks up new
  #     IGLOO_* knobs automatically.
  # igloo_init is saved into a non-exported shell var first since we exec it.
  # A few knobs are deliberately KEPT because guest tooling reads them from
  # inside the firmware process tree:
  #   IGLOO_LTRACE / IGLOO_LTRACE_EXCLUDED -- ltrace LD_PRELOAD constructor
  #   PROJ_NAME                            -- injected guest test tooling
  real_init="${igloo_init}"
  unset IGLOO_NO_SHELL_COV
  if [ -f /igloo/boot/igloo_env.sh ]; then
    igloo_keep=" IGLOO_LTRACE IGLOO_LTRACE_EXCLUDED PROJ_NAME "
    for igloo_v in $(/igloo/utils/busybox sed -n 's/^export \([A-Za-z_][A-Za-z0-9_]*\)=.*/\1/p' /igloo/boot/igloo_env.sh); do
      case "$igloo_keep" in *" $igloo_v "*) continue ;; esac
      unset "$igloo_v"
    done
    unset igloo_keep igloo_v
  fi
  unset igloo_init
  # Run the real guest init in a fresh UTS namespace. This marks the
  # firmware-under-analysis process subtree (which inherits the namespace) as
  # distinct from Penguin's own infrastructure, which stays in the initial
  # namespace; syscall/exec analysis loggers are scoped on that distinction. If
  # the kernel lacks CONFIG_UTS_NS, fall back to a plain exec so boot still works.
  if /igloo/utils/busybox unshare -u /igloo/utils/busybox true >/dev/null 2>&1; then
    exec /igloo/utils/busybox unshare -u "${real_init}"
  fi
  exec "${real_init}"
fi
echo "[IGLOO INIT] Fatal: no igloo_init specified in env. Abort"
exit 1
