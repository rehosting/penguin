"""Host-side harness coverage for the Netdevs API plugin (pyplugins/apis/net.py).

The feature under test: ``Netdevs.ensure_netdev_from_path()`` auto-creates an
igloonet stub netdev for interface names it sees in a scraped/configured
``/proc/sys/net/ipv[46]/{conf,neigh}/<dev>/`` or ``/sys/class/net/<dev>/``
pseudofile path. That is correct for physical interfaces the firmware expects to
already exist, but harmful for devices userspace/firmware builds at runtime --
bridges (``brctl addbr``), bonds, and VLANs (``vconfig add``): a pre-created stub
claims the name first (firmware creation then fails EEXIST) and, having no
bridge/bond semantics, makes every subsequent management ioctl return EOPNOTSUPP.
So those families must NOT be auto-registered from a path; the escape hatch is
listing the name explicitly in the ``netdevs`` config (which calls
``register_netdev`` directly, bypassing this path entirely).

This plugin sits *behind the FFI-enum boundary* (``from hyper.portal import
PortalCmd`` builds ``hyper.consts`` at import), so it is loaded with ``real_isf=``
-- the real published driver ISF read through ``dwarffi`` -- via the
``igloo_ko_isf`` session fixture. All logic exercised here is pure host-side: no
PANDA, no guest, no per-arch boot. ``ensure_netdev_from_path`` queues names into
``_pending_netdevs`` (the kernel REGISTER_NETDEV round-trip is a guest edge and
stays a tests/integration fixture), so we assert on that queue directly.
"""
from pathlib import Path

import pytest

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
NET = str(REPO_ROOT / "pyplugins" / "apis" / "net.py")


def _load(isf, netdevs=None):
    return load_pyplugin(
        NET, real_isf=isf, args={"conf": {"netdevs": netdevs or []}})


# Every path family ensure_netdev_from_path() extracts an interface from. The
# decision must not depend on which pseudofile tree referenced the device.
def _paths(iface):
    return [
        f"/proc/sys/net/ipv4/conf/{iface}/rp_filter",
        f"/proc/sys/net/ipv6/conf/{iface}/forwarding",
        f"/proc/sys/net/ipv4/neigh/{iface}/retrans_time",
        f"/proc/sys/net/ipv6/neigh/{iface}/base_reachable_time",
        f"/sys/class/net/{iface}/statistics/rx_bytes",
        f"/sys/devices/virtual/net/{iface}/flags",
    ]


def _auto_registers(isf, iface):
    """Feed every pseudofile-path family for ``iface`` (each into its own clean
    plugin, so dedup can't mask a per-family miss) and report whether the plugin
    auto-registered it. Asserts the decision is consistent across all path
    families -- it keys off the name, not which tree referenced it."""
    outcomes = set()
    for path in _paths(iface):
        p = _load(isf).plugin
        p.ensure_netdev_from_path(path)
        outcomes.add(iface in p._pending_netdevs)
    assert len(outcomes) == 1, f"{iface}: inconsistent across path families"
    return outcomes.pop()


# --- the plugin imports/constructs at all (enum boundary crossed) ----------- #
def test_plugin_loads_behind_enum_boundary(igloo_ko_isf):
    lp = _load(igloo_ko_isf)
    assert type(lp.plugin).__name__ == "Netdevs"
    assert lp.plugin._pending_netdevs == []


# --- firmware-built BRIDGE -> no stub netdev auto-created ------------------- #
@pytest.mark.parametrize("iface", ["br0", "br1", "br-lan", "bridge0"])
def test_bridge_not_auto_created(igloo_ko_isf, iface):
    p = _load(igloo_ko_isf).plugin
    assert p._is_runtime_created_iface(iface) is True
    p.ensure_netdev_from_path(f"/proc/sys/net/ipv4/conf/{iface}/proxy_arp")
    assert iface not in p._pending_netdevs
    assert iface not in p._netdev_classes


# --- firmware-built BOND -> no stub netdev auto-created --------------------- #
@pytest.mark.parametrize("iface", ["bond0", "bond1"])
def test_bond_not_auto_created(igloo_ko_isf, iface):
    p = _load(igloo_ko_isf).plugin
    assert p._is_runtime_created_iface(iface) is True
    p.ensure_netdev_from_path(f"/sys/class/net/{iface}/statistics/rx_bytes")
    assert iface not in p._pending_netdevs


# --- firmware-built VLAN -> no stub netdev auto-created --------------------- #
# Both the vlanNNN form and the dotted sub-interface form (eth0.100 / eth0.1).
@pytest.mark.parametrize("iface", ["vlan100", "eth0.100", "eth0.1", "eth1.4094"])
def test_vlan_not_auto_created(igloo_ko_isf, iface):
    p = _load(igloo_ko_isf).plugin
    assert p._is_runtime_created_iface(iface) is True
    p.ensure_netdev_from_path(f"/proc/sys/net/ipv4/conf/{iface}/forwarding")
    assert iface not in p._pending_netdevs


# --- REGRESSION: real physical interfaces ARE still auto-created ------------ #
# The suppression must not over-reach: ordinary NIC names still get a stub, and
# the decision is the same no matter which pseudofile tree referenced them.
@pytest.mark.parametrize(
    "iface", ["eth0", "eth1", "wlan0", "ra0", "nd0", "end4", "sample0", "lan1"])
def test_real_interface_auto_created(igloo_ko_isf, iface):
    p = _load(igloo_ko_isf).plugin
    assert p._is_runtime_created_iface(iface) is False
    assert _auto_registers(igloo_ko_isf, iface) is True


# --- escape hatch: an explicit netdevs-config name is created regardless ----- #
# Names in the `netdevs` config go through register_netdev directly (never
# ensure_netdev_from_path), so even a bridge/VLAN name is honoured when the user
# asks for it by hand -- the documented override for a target that genuinely
# needs a pre-created stub.
@pytest.mark.parametrize("iface", ["br0", "eth0.0", "bond0", "eth0"])
def test_explicit_config_netdev_bypasses_suppression(igloo_ko_isf, iface):
    p = _load(igloo_ko_isf, netdevs=[iface]).plugin
    assert iface in p._pending_netdevs


# --- edge cases in the decision path ---------------------------------------- #
def test_special_conf_names_never_registered(igloo_ko_isf):
    # "all"/"default"/"lo" are conf pseudo-entries, not interfaces.
    p = _load(igloo_ko_isf).plugin
    for name in ("all", "default", "lo"):
        p.ensure_netdev_from_path(f"/proc/sys/net/ipv4/conf/{name}/forwarding")
    assert p._pending_netdevs == []


def test_invalid_iface_name_not_registered(igloo_ko_isf):
    # A name failing VALID_IFACE_PATTERN (e.g. the ".."/"." placeholders) must
    # not be registered, and must not be misread as a dotted VLAN either.
    p = _load(igloo_ko_isf).plugin
    for name in ("..", "."):
        p.ensure_netdev_from_path(f"/proc/sys/net/ipv4/conf/{name}/forwarding")
    assert p._pending_netdevs == []


def test_non_network_path_is_noop(igloo_ko_isf):
    p = _load(igloo_ko_isf).plugin
    p.ensure_netdev_from_path("/proc/sys/kernel/hostname")
    p.ensure_netdev_from_path("/dev/null")
    p.ensure_netdev_from_path("")
    assert p._pending_netdevs == []


def test_auto_register_is_idempotent(igloo_ko_isf):
    # A real iface seen twice (or already pending) is queued once.
    p = _load(igloo_ko_isf).plugin
    p.ensure_netdev_from_path("/proc/sys/net/ipv4/conf/eth0/rp_filter")
    p.ensure_netdev_from_path("/sys/class/net/eth0/statistics/rx_bytes")
    assert p._pending_netdevs.count("eth0") == 1


def test_nested_vlan_over_bond_suppressed(igloo_ko_isf):
    # A VLAN stacked on a bond (bond0.100) is dotted -> a runtime-created VLAN,
    # so it is suppressed just like any other VLAN sub-interface.
    p = _load(igloo_ko_isf).plugin
    assert p._is_runtime_created_iface("bond0.100") is True
    p.ensure_netdev_from_path("/proc/sys/net/ipv4/conf/bond0.100/forwarding")
    assert "bond0.100" not in p._pending_netdevs


def test_mixed_config_suppresses_only_runtime_families(igloo_ko_isf):
    # A target whose config lists a real NIC and a bridge, then touches more
    # devices at runtime: config names are honoured; runtime-scraped bridges/
    # VLANs are suppressed while real NICs are still created.
    p = _load(igloo_ko_isf, netdevs=["eth0", "br0"]).plugin
    assert set(p._pending_netdevs) == {"eth0", "br0"}         # both explicit
    p.ensure_netdev_from_path("/proc/sys/net/ipv4/conf/br1/proxy_arp")   # bridge
    p.ensure_netdev_from_path("/proc/sys/net/ipv4/conf/eth1/rp_filter")  # real
    p.ensure_netdev_from_path("/proc/sys/net/ipv4/conf/eth1.5/forwarding")  # VLAN
    assert "br1" not in p._pending_netdevs
    assert "eth1.5" not in p._pending_netdevs
    assert "eth1" in p._pending_netdevs


def test_names_that_look_like_but_are_not_runtime_families(igloo_ko_isf):
    # Documents the boundary of RUNTIME_CREATED_IFACE: a "br"/"bond"/"vlan"
    # prefix WITHOUT a following digit or dash is a plain NIC name, not a
    # bridge/bond/VLAN, so it is still auto-created. (Notably wlan0 must not be
    # read as a VLAN.)
    p = _load(igloo_ko_isf).plugin
    for iface in ("wlan0", "brine0", "bonjour0", "vlanish"):
        assert p._is_runtime_created_iface(iface) is False, iface
        assert _auto_registers(igloo_ko_isf, iface) is True
