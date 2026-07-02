"""
Tests for penguin.manager.calculate_score, focused on the crashes category
(crashes.yaml written by the crashes plugin).
"""

import pytest
import yaml

from penguin.manager import SCORE_CATEGORIES, calculate_score


@pytest.fixture
def result_dir(tmp_path):
    """A minimal valid result dir: just the .ran marker."""
    (tmp_path / ".ran").touch()
    return tmp_path


def test_score_has_all_categories(result_dir):
    score = calculate_score(str(result_dir), have_console=False)
    assert set(score.keys()) == set(SCORE_CATEGORIES)


def test_crashes_score_missing_file(result_dir):
    score = calculate_score(str(result_dir), have_console=False)
    assert score["crashes"] == 0


def test_crashes_score_empty_report(result_dir):
    (result_dir / "crashes.yaml").write_text("crashes: []\n")
    score = calculate_score(str(result_dir), have_console=False)
    assert score["crashes"] == 0


def test_crashes_score_counts_deduped_records(result_dir):
    records = [
        {"proc": "httpd", "pid": 412, "signal": 11, "signame": "SIGSEGV",
         "pc": "0x004013a8", "time": 12.481, "count": 3},
        {"proc": "upnpd", "pid": 500, "signal": 6, "signame": "SIGABRT",
         "pc": "0x00021bcc", "time": 20.1, "count": 1},
    ]
    with open(result_dir / "crashes.yaml", "w") as f:
        yaml.safe_dump({"crashes": records}, f, sort_keys=False)

    score = calculate_score(str(result_dir), have_console=False)
    # Negative, and per unique record -- not per delivery (count is ignored).
    assert score["crashes"] == -2


def test_crashes_score_corrupt_file(result_dir):
    (result_dir / "crashes.yaml").write_text("{not valid: yaml: [")
    score = calculate_score(str(result_dir), have_console=False)
    assert score["crashes"] == 0
