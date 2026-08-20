"""Host-side tests for the `penguin docs` subcommand.

Bare `penguin docs` offers an interactive chooser (`gum choose`), which needs a
controlling terminal and only exists inside the penguin image. Neither is
available to a script or a CI job, so both must fall back to printing the page
list rather than dead-ending -- which is what `--filename`'s help has always
promised.
"""
from unittest.mock import patch

import pytest
from click.testing import CliRunner

import penguin.__main__ as m

PAGES = ["playbook.md", "plugins.md", "sub/nested.md"]


def _invoke(args=(), **kwargs):
    with patch.object(m, "_startup_checks"), \
            patch.object(m, "_render_markdown_file") as render, \
            patch("penguin.__main__.glob.glob", return_value=list(PAGES)), \
            patch("penguin.__main__.os.path.isfile", return_value=True):
        result = CliRunner().invoke(
            m.cli, ["docs", *args], obj={"VERBOSE": False},
            standalone_mode=False, **kwargs,
        )
    return result, render


def test_no_gum_lists_pages_instead_of_raising():
    """gum absent used to raise an uncaught FileNotFoundError."""
    with patch("penguin.__main__.subprocess.run", side_effect=FileNotFoundError("gum")):
        result, render = _invoke()
    assert result.exit_code == 0
    for page in PAGES:
        assert page in result.output
    render.assert_not_called()


def test_no_tty_lists_pages_instead_of_exiting_silently():
    """gum present but no controlling terminal: it exits nonzero.

    This used to `return` with nothing printed, so a script got success and no
    output -- worse than an error.
    """
    failed = type("R", (), {"returncode": 1, "stdout": "", "stderr": "could not open a new TTY"})
    with patch("penguin.__main__.subprocess.run", return_value=failed()):
        result, render = _invoke()
    assert result.exit_code == 0
    assert "playbook.md" in result.output
    assert "--filename" in result.output      # tells the user how to render one
    render.assert_not_called()


def test_interactive_choice_is_rendered():
    """When the chooser works, its selection is still rendered as before."""
    chosen = type("R", (), {"returncode": 0, "stdout": "plugins.md\n", "stderr": ""})
    with patch("penguin.__main__.subprocess.run", return_value=chosen()):
        result, render = _invoke()
    assert result.exit_code == 0
    render.assert_called_once()
    assert render.call_args[0][0].endswith("plugins.md")


def test_empty_chooser_output_falls_back_to_the_list():
    """A cancelled chooser (exit 0, no selection) must not render "".md."""
    empty = type("R", (), {"returncode": 0, "stdout": "\n", "stderr": ""})
    with patch("penguin.__main__.subprocess.run", return_value=empty()):
        result, render = _invoke()
    assert result.exit_code == 0
    render.assert_not_called()


def test_filename_still_bypasses_the_chooser():
    with patch("penguin.__main__.subprocess.run") as run:
        result, render = _invoke(["--filename", "playbook.md"])
    assert result.exit_code == 0
    run.assert_not_called()
    render.assert_called_once()


def test_missing_named_page_is_an_error():
    """`--filename typo.md` used to log at info level and exit 0."""
    with patch.object(m, "_startup_checks"), \
            patch.object(m, "_render_markdown_file") as render, \
            patch("penguin.__main__.os.path.isfile", return_value=False):
        result = CliRunner().invoke(m.cli, ["docs", "--filename", "typo.md"],
                                    obj={"VERBOSE": False}, standalone_mode=False)
    assert result.exit_code != 0
    render.assert_not_called()


def test_no_pages_at_all_is_an_error():
    with patch.object(m, "_startup_checks"), \
            patch("penguin.__main__.glob.glob", return_value=[]):
        result = CliRunner().invoke(m.cli, ["docs"], obj={"VERBOSE": False},
                                    standalone_mode=False)
    assert result.exit_code != 0


# --------------------------------------------------------------- pager sizing

@pytest.mark.parametrize("num_lines,expect_pager", [(10, False), (500, True)])
def test_pager_uses_terminal_lines_not_columns(tmp_path, num_lines, expect_pager):
    """`os.get_terminal_size()` is (columns, lines).

    Unpacking it as `rows, _` compared a line count against the terminal
    *width*, so a 100-line page in an 80x24 terminal skipped the pager.
    """
    page = tmp_path / "p.md"
    page.write_text("x\n" * num_lines)
    size = type("S", (), {"columns": 80, "lines": 24})

    with patch("penguin.__main__.shutil.which", return_value="/usr/bin/glow"), \
            patch("penguin.__main__.shutil.get_terminal_size", return_value=size()), \
            patch("penguin.__main__.sys.stdout") as stdout, \
            patch("penguin.__main__.subprocess.run") as run:
        stdout.isatty.return_value = True
        m._render_markdown_file(str(page), num_lines=num_lines)

    args = run.call_args[0][0]
    assert ("--pager" in args) is expect_pager


def test_no_pager_when_stdout_is_not_a_terminal(tmp_path):
    page = tmp_path / "p.md"
    page.write_text("x\n" * 500)
    with patch("penguin.__main__.shutil.which", return_value="/usr/bin/glow"), \
            patch("penguin.__main__.sys.stdout") as stdout, \
            patch("penguin.__main__.subprocess.run") as run:
        stdout.isatty.return_value = False
        m._render_markdown_file(str(page), num_lines=500)
    assert "--pager" not in run.call_args[0][0]
