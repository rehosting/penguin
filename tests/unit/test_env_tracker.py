"""In-place harness coverage for the EnvTracker analysis plugin
(pyplugins/analysis/env.py), driven host-side with no PANDA/guest.

EnvTracker records environment variables the guest reads (getenv) or compares
(strstr) and, on teardown, writes the ones not already configured to
``env_missing.yaml``. A second, differently-shaped plugin exercising the harness:
YAML output flushed on ``uninit`` rather than per-event CSV.
"""
from pathlib import Path

from penguin import yaml
from penguin.testing import load_pyplugin

REPO_ROOT = Path(__file__).resolve().parents[2]
ENV = REPO_ROOT / "pyplugins" / "analysis" / "env.py"


def _load_env(tmp_path, conf=None):
    return load_pyplugin(
        str(ENV), outdir=tmp_path, class_name="EnvTracker",
        args={"conf": conf or {}},
    )


def test_getenv_records_interesting_var_as_missing(tmp_path):
    lp = _load_env(tmp_path)
    lp.dispatch("igloo_getenv", None, "FOOBAR_APP_KEY")  # interesting, not configured
    lp.dispatch("igloo_getenv", None, "LD_PRELOAD")       # LD_ prefix -> ignored
    lp.finalize()  # uninit() dumps env_missing.yaml

    missing = yaml.safe_load((tmp_path / "env_missing.yaml").read_text())
    assert "FOOBAR_APP_KEY" in missing
    assert "LD_PRELOAD" not in missing


def test_configured_env_var_not_reported_missing(tmp_path):
    # A var already set in the config's env: is known, so it isn't "missing".
    lp = _load_env(tmp_path, conf={"env": {"FOOBAR_APP_KEY": "1"}})
    lp.dispatch("igloo_getenv", None, "FOOBAR_APP_KEY")
    lp.finalize()
    missing = yaml.safe_load((tmp_path / "env_missing.yaml").read_text())
    assert "FOOBAR_APP_KEY" not in missing


def test_uboot_var_captured_via_strstr(tmp_path):
    # The uboot placeholder marker in one strstr operand flags the other as a
    # u-boot env lookup; it lands in env_uboot.txt on teardown.
    lp = _load_env(tmp_path)
    lp.dispatch("igloo_strstr", None, "igloo_uboot_env=placeholder", "bootcmd=")
    lp.finalize()
    uboot = yaml.safe_load((tmp_path / "env_uboot.txt").read_text())
    assert "bootcmd" in uboot
