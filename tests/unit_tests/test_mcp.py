"""Unit tests for the dependency-free MCP helpers (no container, no `mcp` package)."""

import os
import sqlite3

import yaml

from penguin.mcp import diagnostics as diag
from penguin.mcp import mutations as mut


# --- mutations ------------------------------------------------------------------------

def test_mutations_accumulate_into_one_patch(tmp_path):
    proj = str(tmp_path)
    mut.set_env(proj, "igloo_init", "/sbin/init")
    mut.set_nvram(proj, "lan_ipaddr", "192.168.1.1")
    mut.add_netdev(proj, "eth0")
    mut.add_netdev(proj, "eth0")  # dedup
    mut.add_netdev(proj, "vlan1")
    mut.block_signal(proj, 6)
    mut.add_pseudofile(proj, "/dev/foo", ioctl={"*": {"model": "return_const", "val": 0}})

    patch_path = os.path.join(proj, "patch_90_mcp.yaml")
    assert os.path.exists(patch_path)
    with open(patch_path) as f:
        patch = yaml.safe_load(f)

    assert patch["env"]["igloo_init"] == "/sbin/init"
    assert patch["nvram"]["lan_ipaddr"] == "192.168.1.1"
    assert patch["netdevs"] == ["eth0", "vlan1"]  # deduped, ordered
    assert patch["blocked_signals"] == [6]
    assert patch["pseudofiles"]["/dev/foo"]["ioctl"]["*"]["model"] == "return_const"


def test_show_and_reset_patch(tmp_path):
    proj = str(tmp_path)
    assert mut.show_patch(proj)["exists"] is False
    mut.set_env(proj, "FOO", "bar")
    shown = mut.show_patch(proj)
    assert shown["exists"] is True and shown["patch"]["env"]["FOO"] == "bar"
    assert mut.reset_patch(proj)["removed"] is True
    assert not os.path.exists(os.path.join(proj, "patch_90_mcp.yaml"))
    assert mut.reset_patch(proj)["removed"] is False


def test_deep_merge_overwrites_scalar_keeps_siblings(tmp_path):
    proj = str(tmp_path)
    mut.set_env(proj, "A", "1")
    mut.set_env(proj, "B", "2")
    patch = mut.set_env(proj, "A", "3")  # overwrite A, keep B
    assert patch["env"] == {"A": "3", "B": "2"}


# --- diagnostics ----------------------------------------------------------------------

def _mk_results(tmp_path):
    proj = tmp_path
    rd = proj / "results" / "0"
    rd.mkdir(parents=True)
    (proj / "results" / "latest").symlink_to("./0")
    return str(proj), str(rd)


def test_latest_results_resolves_symlink(tmp_path):
    proj, rd = _mk_results(tmp_path)
    assert os.path.realpath(diag.latest_results(proj)) == os.path.realpath(rd)


def test_readers_parse_artifacts(tmp_path):
    proj, rd = _mk_results(tmp_path)
    with open(os.path.join(rd, "health_final.yaml"), "w") as f:
        yaml.safe_dump({"nopanic": 1, "bound_sockets": 3}, f)
    with open(os.path.join(rd, "env_missing.yaml"), "w") as f:
        yaml.safe_dump(["sxid", "boardmodel"], f)
    with open(os.path.join(rd, "pseudofiles_failures.yaml"), "w") as f:
        yaml.safe_dump({"/dev/dsa": {"ioctl": 5}}, f)
    with open(os.path.join(rd, "netbinds.csv"), "w") as f:
        f.write("httpd,4,tcp,0.0.0.0,80\ntelnetd,4,tcp,0.0.0.0,23\n")
    with open(os.path.join(rd, "console.log"), "w") as f:
        f.write("boot ok\nKernel panic - not syncing: Attempted to kill init!\ndone\n")

    assert diag.read_health(proj_dir=proj)["health"]["bound_sockets"] == 3
    assert "sxid" in diag.read_missing_env(proj_dir=proj)["missing_env"]
    assert diag.read_pseudofile_failures(proj_dir=proj)["pseudofile_failures"]["/dev/dsa"]
    nb = diag.read_netbinds(proj_dir=proj)
    assert nb["count"] == 2 and nb["netbinds"][0][0] == "httpd"
    panic = diag.grep_console(proj_dir=proj, pattern="panic")
    assert panic["total_matched"] == 1 and "Attempted to kill init" in panic["lines"][0]


def test_missing_file_returns_error_not_raise(tmp_path):
    proj, _ = _mk_results(tmp_path)
    assert "error" in diag.read_health(proj_dir=proj)  # no health_final.yaml written


def test_db_query_readonly_guard_and_select(tmp_path):
    proj, rd = _mk_results(tmp_path)
    db = os.path.join(rd, "plugins.db")
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE event (id INTEGER PRIMARY KEY, procname TEXT)")
    con.execute("INSERT INTO event VALUES (1, 'httpd')")
    con.commit()
    con.close()

    assert diag.query_db("DROP TABLE event", proj_dir=proj)["error"]
    assert diag.query_db("SELECT 1; DELETE FROM event", proj_dir=proj)["error"]
    rows = diag.query_db("SELECT procname FROM event", proj_dir=proj)
    assert rows["rows"][0]["procname"] == "httpd"
