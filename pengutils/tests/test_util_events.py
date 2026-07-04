"""Host-side smoke tests for pengutils utility helpers (no guest/DB)."""
import pytest

from pengutils.utils import util_events, util_base


def test_in_container_reflects_env(monkeypatch):
    monkeypatch.delenv("PENGUIN_PROJECT_DIR", raising=False)
    assert util_events.in_container() is False
    monkeypatch.setenv("PENGUIN_PROJECT_DIR", "/proj")
    assert util_events.in_container() is True


def test_default_socket_path_in_container(monkeypatch):
    monkeypatch.setenv("PENGUIN_PROJECT_DIR", "/proj")
    assert util_events.get_default_socket_path() == "/proj/results/latest/remotectrl.sock"


def test_default_socket_path_requires_container(monkeypatch):
    monkeypatch.delenv("PENGUIN_PROJECT_DIR", raising=False)
    with pytest.raises(Exception):
        util_events.get_default_socket_path()


def test_default_results_path():
    assert util_base.get_default_results_path() == "/workspace/results/latest"
