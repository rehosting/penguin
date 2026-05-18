OUT=/igloo/shared/diagnostics

set_backend_with_update_alternatives() {
  name="$1"
  target="$2"

  if command -v update-alternatives >/dev/null 2>&1; then
    if update-alternatives --query "$name" 2>/dev/null | /igloo/utils/busybox grep -Fq "Alternative: $target"; then
      update-alternatives --set "$name" "$target"
      return 0
    fi
  fi

  return 1
}

set_backend_with_alternatives() {
  name="$1"
  target="$2"

  if command -v alternatives >/dev/null 2>&1; then
    alternatives --set "$name" "$target" >/dev/null 2>&1
    return $?
  fi

  return 1
}

set_backend_with_symlink() {
  link_path="$1"
  target="$2"

  if [ -L "$link_path" ] && [ -e "$target" ]; then
    /igloo/utils/busybox ln -sf "$target" "$link_path"
    return 0
  fi

  return 1
}

set_iptables_backend() {
  if [ "$1" = "legacy" ]; then
    set_backend_with_update_alternatives iptables /usr/sbin/iptables-legacy \
      || set_backend_with_alternatives iptables /usr/sbin/iptables-legacy \
      || set_backend_with_symlink /usr/sbin/iptables /usr/sbin/iptables-legacy
    set_backend_with_update_alternatives ip6tables /usr/sbin/ip6tables-legacy \
      || set_backend_with_alternatives ip6tables /usr/sbin/ip6tables-legacy \
      || set_backend_with_symlink /usr/sbin/ip6tables /usr/sbin/ip6tables-legacy
    set_backend_with_update_alternatives arptables /usr/sbin/arptables-legacy \
      || set_backend_with_alternatives arptables /usr/sbin/arptables-legacy \
      || set_backend_with_symlink /usr/sbin/arptables /usr/sbin/arptables-legacy
    set_backend_with_update_alternatives ebtables /usr/sbin/ebtables-legacy \
      || set_backend_with_alternatives ebtables /usr/sbin/ebtables-legacy \
      || set_backend_with_symlink /usr/sbin/ebtables /usr/sbin/ebtables-legacy
  fi
}

mkdir -p "$OUT"

if [ ! -z "${IGLOO_IPTABLES_BACKEND}" ]; then
  set_iptables_backend "$IGLOO_IPTABLES_BACKEND"
fi

{
  echo "timestamp=$(date -Is)"
  echo "kernel=$(/igloo/utils/busybox uname -r)"
  echo "cgroup_mode=${IGLOO_CGROUP_MODE:-unset}"
  echo "iptables_backend=${IGLOO_IPTABLES_BACKEND:-unset}"
} > "$OUT/compat_mode.txt"

if command -v iptables >/dev/null 2>&1; then
  iptables --version > "$OUT/iptables_version.txt" 2>&1 || true
fi

if command -v ip6tables >/dev/null 2>&1; then
  ip6tables --version > "$OUT/ip6tables_version.txt" 2>&1 || true
fi

if command -v update-alternatives >/dev/null 2>&1; then
  update-alternatives --query iptables > "$OUT/iptables_alternatives.txt" 2>&1 || true
  update-alternatives --query ip6tables >> "$OUT/iptables_alternatives.txt" 2>&1 || true
fi
