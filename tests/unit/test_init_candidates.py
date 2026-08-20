"""Host-side tests for `get_inits_from_proj` (penguin.common).

The statically-identified init candidates live in `static/InitFinder.yaml` (a
plain list, shortest path first -- `InitFinder.inits` returns `list[str]`).
Three call sites read it, and one of them does `len(options)`, so the helper
must return a list even when the project has no such file.
"""
from penguin.common import get_inits_from_proj


def _project(tmp_path, contents=None):
    if contents is not None:
        static = tmp_path / "static"
        static.mkdir(exist_ok=True)
        (static / "InitFinder.yaml").write_text(contents)
    return str(tmp_path)


def test_missing_project_dir_is_an_empty_list():
    assert get_inits_from_proj("/nonexistent-project") == []


def test_missing_file_is_an_empty_list(tmp_path):
    assert get_inits_from_proj(_project(tmp_path)) == []


def test_empty_file_is_an_empty_list(tmp_path):
    """An empty YAML document parses to None, which callers cannot len()."""
    assert get_inits_from_proj(_project(tmp_path, "")) == []


def test_candidates_are_returned_in_file_order(tmp_path):
    proj = _project(tmp_path, "- /init\n- /etc/init.d/rcS\n- /sbin/init\n")
    assert get_inits_from_proj(proj) == ["/init", "/etc/init.d/rcS", "/sbin/init"]


def test_result_supports_the_caller_access_pattern(tmp_path):
    """`if len(options): options[0]` -- used verbatim by `penguin run`."""
    for contents in (None, "", "- /sbin/init\n"):
        options = get_inits_from_proj(_project(tmp_path, contents))
        assert len(options) in (0, 1)
        if len(options):
            assert options[0] == "/sbin/init"
