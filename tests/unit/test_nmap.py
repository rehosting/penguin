"""In-place harness coverage for the Nmap actuation plugin
(pyplugins/actuation/nmap.py), driven host-side with no PANDA/guest.

Nmap subscribes to the VPN's ``on_bind`` and launches ``nmap`` against each new
TCP service. We don't run nmap: the testable host logic is the UDP short-circuit,
the scan-command construction (incl. the custom-nmap redirect branch), and the
subprocess bookkeeping, so we drive ``scan_thread`` directly with ``subprocess``
patched.
"""
from pathlib import Path
from unittest import mock

from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
NMAP = REPO_ROOT / "pyplugins" / "actuation" / "nmap.py"


def test_on_bind_ignores_udp(tmp_path):
    lp = load_pyplugin(str(NMAP), outdir=tmp_path)
    lp.plugin.nmap_on_bind("udp", "10.0.0.1", 53, 5300, "127.0.0.1", "dnsmasq")
    assert list(tmp_path.iterdir()) == []  # no scan file, no thread


def test_scan_thread_builds_basic_command(tmp_path):
    lp = load_pyplugin(str(NMAP), outdir=tmp_path)
    lp.plugin.custom_nmap = False
    with mock.patch("subprocess.Popen") as popen:
        popen.return_value.wait.return_value = 0
        lp.plugin.scan_thread("127.0.0.1", 80, 8080, str(tmp_path / "o.xml"))
    cmd = popen.call_args.args[0]
    assert cmd[0] == "nmap" and "-p8080" in cmd and "-sV" in cmd
    assert lp.plugin.subprocesses == []  # tracked during, removed after wait()


def test_scan_thread_uses_redirect_with_custom_nmap(tmp_path):
    lp = load_pyplugin(str(NMAP), outdir=tmp_path)
    lp.plugin.custom_nmap = True
    with mock.patch("subprocess.Popen") as popen:
        popen.return_value.wait.return_value = 0
        lp.plugin.scan_thread("127.0.0.1", 80, 8080, str(tmp_path / "o.xml"))
    cmd = popen.call_args.args[0]
    assert "--redirect-port" in cmd and "-p80" in cmd


def test_uninit_terminates_running_scans(tmp_path):
    lp = load_pyplugin(str(NMAP), outdir=tmp_path)
    proc = mock.Mock()
    lp.plugin.subprocesses.append(proc)
    lp.finalize()  # uninit -> cleanup_subprocesses
    proc.terminate.assert_called_once()
    proc.kill.assert_called_once()
    assert lp.plugin.subprocesses == []
