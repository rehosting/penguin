"""
Unit tests for penguin.compose — pure logic only, no QEMU required.
"""
import os
import sys
import tempfile
import unittest

sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../../src")))
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "../..")))

from penguin.compose import (  # noqa: E402
    MCAST_BASE_PORT,
    MCAST_GROUP,
    ComposeConfig,
    DeviceConfig,
    DeviceNetAttachment,
    NetworkSpec,
    _build_compose_patch,
    _deep_merge,
    _generate_mac,
    load_compose,
)


MINIMAL_COMPOSE = """\
version: 1

networks:
  lan:
    subnet: 192.168.1.0/24

devices:
  router:
    project: {router_dir}
    networks:
      lan:
        iface: eth0
        ip: 192.168.1.1/24
        mac: "52:54:00:aa:01:01"

  client:
    project: {client_dir}
    networks:
      lan:
        iface: eth0
        ip: 192.168.1.100/24
"""

MINIMAL_CONFIG = """\
core:
  arch: mipsel
  kernel: /igloo_static/kernels/vmlinux.mipsel
  fs: ./base/fs.tar.gz
  timeout: 60
"""


def _make_project_dir(tmpdir, name):
    """Create a minimal project directory with config.yaml."""
    proj = os.path.join(tmpdir, name)
    os.makedirs(os.path.join(proj, "base"), exist_ok=True)
    with open(os.path.join(proj, "config.yaml"), "w") as f:
        f.write(MINIMAL_CONFIG)
    return proj


class TestGenerateMac(unittest.TestCase):
    def test_format(self):
        mac = _generate_mac("/path/to/compose.yaml", "router", "lan")
        parts = mac.split(":")
        self.assertEqual(len(parts), 6)
        for p in parts:
            self.assertEqual(len(p), 2)
            int(p, 16)  # must be valid hex

    def test_locally_administered(self):
        mac = _generate_mac("/path/to/compose.yaml", "router", "lan")
        first = int(mac.split(":")[0], 16)
        self.assertTrue(first & 0x02, "locally-administered bit must be set")
        self.assertFalse(first & 0x01, "multicast bit must be clear")

    def test_deterministic(self):
        a = _generate_mac("/compose.yaml", "router", "lan")
        b = _generate_mac("/compose.yaml", "router", "lan")
        self.assertEqual(a, b)

    def test_unique_per_device(self):
        a = _generate_mac("/compose.yaml", "router", "lan")
        b = _generate_mac("/compose.yaml", "client", "lan")
        self.assertNotEqual(a, b)

    def test_unique_per_network(self):
        a = _generate_mac("/compose.yaml", "router", "lan")
        b = _generate_mac("/compose.yaml", "router", "mgmt")
        self.assertNotEqual(a, b)


class TestDeepMerge(unittest.TestCase):
    def test_simple_override(self):
        base = {"a": 1, "b": 2}
        result = _deep_merge(base, {"b": 99, "c": 3})
        self.assertEqual(result, {"a": 1, "b": 99, "c": 3})

    def test_nested_merge(self):
        base = {"core": {"arch": "mipsel", "timeout": 60}}
        result = _deep_merge(base, {"core": {"timeout": 120}})
        self.assertEqual(result["core"], {"arch": "mipsel", "timeout": 120})

    def test_non_dict_replaces(self):
        base = {"a": [1, 2, 3]}
        result = _deep_merge(base, {"a": [4, 5]})
        self.assertEqual(result["a"], [4, 5])


class TestBuildComposePatch(unittest.TestCase):
    def _make_device(self, name="router", ip=None, mac=None):
        return DeviceConfig(
            name=name,
            proj_dir="/proj",
            config_path="/proj/config.yaml",
            networks=[DeviceNetAttachment(
                network_name="lan",
                iface="eth0",
                ip=ip,
                mac=mac,
            )],
        )

    def _make_networks(self):
        return {"lan": NetworkSpec(name="lan", port=MCAST_BASE_PORT)}

    def test_qemu_args_present(self):
        device = self._make_device(mac="52:54:00:aa:01:01")
        patch = _build_compose_patch(device, self._make_networks(), "/compose.yaml")
        args = patch["core"]["extra_qemu_args"]
        self.assertIn("-netdev socket,id=compose.0", args)
        self.assertIn(f"mcast={MCAST_GROUP}:{MCAST_BASE_PORT}", args)
        self.assertIn("-device virtio-net-pci", args)
        self.assertIn("52:54:00:aa:01:01", args)

    def test_auto_mac_when_none(self):
        device = self._make_device()
        patch = _build_compose_patch(device, self._make_networks(), "/compose.yaml")
        args = patch["core"]["extra_qemu_args"]
        self.assertIn("-device virtio-net-pci", args)
        # MAC auto-generated — just check it's plausible (xx:xx:xx:xx:xx:xx)
        import re
        self.assertTrue(re.search(r'mac=[0-9a-f]{2}(:[0-9a-f]{2}){5}', args))

    def test_no_static_files_without_ip(self):
        device = self._make_device()
        patch = _build_compose_patch(device, self._make_networks(), "/compose.yaml")
        self.assertNotIn("static_files", patch)

    def test_static_files_with_ip(self):
        device = self._make_device(ip="192.168.1.1/24")
        patch = _build_compose_patch(device, self._make_networks(), "/compose.yaml")
        self.assertIn("static_files", patch)
        sf = patch["static_files"]["/igloo/init.d/zz_compose_net"]
        self.assertEqual(sf["type"], "inline_file")
        self.assertIn("ip link set eth0 up", sf["contents"])
        self.assertIn("ip addr add 192.168.1.1/24 dev eth0", sf["contents"])
        self.assertIn("#!/igloo/utils/sh", sf["contents"])

    def test_config_overrides_applied(self):
        device = self._make_device()
        device.config_overrides = {"core": {"timeout": 999}}
        patch = _build_compose_patch(device, self._make_networks(), "/compose.yaml")
        self.assertEqual(patch["core"]["timeout"], 999)
        # extra_qemu_args should still be present alongside timeout
        self.assertIn("extra_qemu_args", patch["core"])

    def test_multiple_networks(self):
        networks = {
            "lan": NetworkSpec(name="lan", port=MCAST_BASE_PORT),
            "mgmt": NetworkSpec(name="mgmt", port=MCAST_BASE_PORT + 1),
        }
        device = DeviceConfig(
            name="router",
            proj_dir="/proj",
            config_path="/proj/config.yaml",
            networks=[
                DeviceNetAttachment("lan", "eth0", ip=None, mac="52:54:00:aa:01:01"),
                DeviceNetAttachment("mgmt", "eth1", ip=None, mac="52:54:00:aa:01:02"),
            ],
        )
        patch = _build_compose_patch(device, networks, "/compose.yaml")
        args = patch["core"]["extra_qemu_args"]
        self.assertIn("compose.0", args)
        self.assertIn("compose.1", args)
        self.assertIn(f":{MCAST_BASE_PORT}", args)
        self.assertIn(f":{MCAST_BASE_PORT + 1}", args)


class TestLoadCompose(unittest.TestCase):
    def setUp(self):
        self.tmpdir = tempfile.mkdtemp()
        self.router_dir = _make_project_dir(self.tmpdir, "router")
        self.client_dir = _make_project_dir(self.tmpdir, "client")
        self.compose_path = os.path.join(self.tmpdir, "compose.yaml")

    def tearDown(self):
        import shutil
        shutil.rmtree(self.tmpdir, ignore_errors=True)

    def _write_compose(self, content):
        with open(self.compose_path, "w") as f:
            f.write(content)

    def test_parse_minimal(self):
        self._write_compose(MINIMAL_COMPOSE.format(
            router_dir=self.router_dir, client_dir=self.client_dir
        ))
        cfg = load_compose(self.compose_path)
        self.assertIsInstance(cfg, ComposeConfig)
        self.assertEqual(cfg.version, 1)
        self.assertIn("lan", cfg.networks)
        self.assertIn("router", cfg.devices)
        self.assertIn("client", cfg.devices)

    def test_port_assignment(self):
        self._write_compose(MINIMAL_COMPOSE.format(
            router_dir=self.router_dir, client_dir=self.client_dir
        ))
        cfg = load_compose(self.compose_path)
        self.assertEqual(cfg.networks["lan"].port, MCAST_BASE_PORT)

    def test_ports_unique_across_networks(self):
        content = f"""\
version: 1
networks:
  alpha:
  beta:
  gamma:
devices:
  dev:
    project: {self.router_dir}
    networks:
      alpha:
        iface: eth0
      beta:
        iface: eth1
      gamma:
        iface: eth2
"""
        self._write_compose(content)
        cfg = load_compose(self.compose_path)
        ports = [cfg.networks[n].port for n in cfg.networks]
        self.assertEqual(len(ports), len(set(ports)), "ports must be unique")

    def test_missing_project_raises(self):
        content = """\
version: 1
networks:
  lan:
devices:
  router:
    project: ./nonexistent
    networks:
      lan:
        iface: eth0
"""
        self._write_compose(content)
        with self.assertRaises(ValueError, msg="Should raise on missing project dir"):
            load_compose(self.compose_path)

    def test_unknown_network_raises(self):
        content = f"""\
version: 1
networks:
  lan:
devices:
  router:
    project: {self.router_dir}
    networks:
      badnet:
        iface: eth0
"""
        self._write_compose(content)
        with self.assertRaises(ValueError):
            load_compose(self.compose_path)

    def test_missing_iface_raises(self):
        content = f"""\
version: 1
networks:
  lan:
devices:
  router:
    project: {self.router_dir}
    networks:
      lan:
        ip: 192.168.1.1/24
"""
        self._write_compose(content)
        with self.assertRaises(ValueError):
            load_compose(self.compose_path)

    def test_mac_in_attachment(self):
        self._write_compose(MINIMAL_COMPOSE.format(
            router_dir=self.router_dir, client_dir=self.client_dir
        ))
        cfg = load_compose(self.compose_path)
        router_net = cfg.devices["router"].networks[0]
        self.assertEqual(router_net.mac, "52:54:00:aa:01:01")

    def test_no_mac_in_attachment(self):
        self._write_compose(MINIMAL_COMPOSE.format(
            router_dir=self.router_dir, client_dir=self.client_dir
        ))
        cfg = load_compose(self.compose_path)
        client_net = cfg.devices["client"].networks[0]
        self.assertIsNone(client_net.mac)  # auto-generated later

    def test_relative_project_path(self):
        """project: path is relative to compose.yaml location."""
        content = """\
version: 1
networks:
  lan:
devices:
  router:
    project: ./router
    networks:
      lan:
        iface: eth0
"""
        self._write_compose(content)
        cfg = load_compose(self.compose_path)
        self.assertEqual(cfg.devices["router"].proj_dir, self.router_dir)


if __name__ == "__main__":
    unittest.main()
