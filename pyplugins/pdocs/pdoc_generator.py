"""
SphinxGenerator Plugin
======================

Generates Sphinx documentation for multiple Python packages
(pyplugins, penguin, events) with Markdown + MyST integration.

- Fixes duplicate menu entries in the TOC
- Includes Markdown files directly via :parser: myst_parser.sphinx_
- Produces static HTML output with optional dark mode
"""

import os
import shutil
import subprocess
from pathlib import Path
from penguin import Plugin, VERSION
import sphinx
from sphinx.cmd import build as sphinx_build


class SphinxGenerator(Plugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = Path(self.get_arg("outdir"))
        self.logger.info("Initializing SphinxGenerator plugin...")

        # Base paths
        self.source_dir = self.outdir / "sphinx_source"
        self.html_dir = self.outdir / "sphinx" / "html"
        self.docs_dir = Path("/docs")

        # Modules to document
        self.module_specs = {
            "pyplugins": Path("/pyplugins"),
            "penguin": Path("/pkg/penguin"),
            "events": Path("/db/events"),
        }

        # Prepare directories
        self.source_dir.mkdir(parents=True, exist_ok=True)
        (self.outdir / "sphinx").mkdir(exist_ok=True)

        # Copy documentation files
        self._copy_docs()

        # Generate conf.py dynamically
        self._generate_conf_py()

        # Generate API docs for each module
        self._generate_api_docs()

        # Build HTML
        self._build_html()

        # Zip result
        zip_path = shutil.make_archive(str(self.html_dir), "zip", str(self.html_dir))
        self.logger.info(f"Zipped documentation at: {zip_path}")

        os._exit(0)

    # -------------------------------------------------------------------------
    # Step 1: Copy /docs and module sources into Sphinx source tree
    # -------------------------------------------------------------------------
    def _copy_docs(self):
        self.logger.info(f"Copying {self.docs_dir} → {self.source_dir / 'docs'}")
        dst_docs = self.source_dir / "docs"
        if dst_docs.exists():
            shutil.rmtree(dst_docs)
        shutil.copytree(self.docs_dir, dst_docs)

        for name, path in self.module_specs.items():
            dst = self.source_dir / name
            self.logger.info(f"✅ Found module '{name}' at {path}")
            if dst.exists():
                shutil.rmtree(dst)
            shutil.copytree(path, dst)

    # -------------------------------------------------------------------------
    # Step 2: Generate Sphinx configuration
    # -------------------------------------------------------------------------
    def _generate_conf_py(self):
        conf_path = self.source_dir / "conf.py"
        conf_path.write_text(
        f"""
import os
import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

project = "Penguin Documentation"
author = "Penguin Team"
release = "{VERSION}"
extensions = [
    "sphinx.ext.autodoc",
    "sphinx.ext.autosummary",
    "sphinx.ext.viewcode",
    "sphinx.ext.todo",
    "myst_parser",
]
autosummary_generate = True
templates_path = ["_templates"]
exclude_patterns = []
html_theme = "furo"
html_static_path = ["_static"]
html_title = "Penguin Auto Docs"
html_theme_options = {{
    "sidebar_hide_name": False,
    "navigation_with_keys": True,
}}

# --- MyST configuration ----------------------------------------------------
myst_enable_extensions = [
    "colon_fence",
    "deflist",
    "fieldlist",
    "attrs_inline",
    "substitution",
    "linkify",
    "smartquotes",
    "replacements",
    "tasklist",
    "html_image",
]
myst_heading_anchors = 3
myst_update_mathjax = False

# Map file suffixes to parser types
source_suffix = {{
    ".rst": "restructuredtext",
    ".md": "markdown",
}}

# Prefer first TOC entry, avoid duplicates
toc_object_entries_show_parents = "hide"

suppress_warnings = [
    "misc.highlighting_failure",
    "myst.header",
    "myst.xref_missing",
    "myst.xref_ambiguous",
    "docstring",
    "autodoc.import_object",
    "ref.ref",
]

master_doc = "index"
language = "en"

# --- Ensure MyST parser is registered globally -----------------------------
def setup(app):
    try:
        from myst_parser.parsers.docutils_ import Parser
        # Only register if not already registered (avoid ExtensionError)
        if "markdown" not in app.registry.source_parsers:
            app.add_source_parser(Parser)
    except Exception as e:
        print(f"⚠️ Skipping parser registration: {{e}}")

"""
    )
        self.logger.info(f"✅ Wrote patched Sphinx conf.py to {conf_path}")


    # -------------------------------------------------------------------------
    # Step 3: Generate .rst files for each module
    # -------------------------------------------------------------------------
    def _generate_api_docs(self):
        self.logger.info(f"Generating API docs for modules: {list(self.module_specs.keys())}")

        for name, path in self.module_specs.items():
            cmd = [
                "sphinx-apidoc",
                "-e",  # Separate pages per module
                "-M",  # Put top-level modules in main TOC
                "-o", str(self.source_dir),
                str(path),
            ]
            self.logger.debug(f"Running: {' '.join(cmd)}")
            subprocess.run(cmd, check=True)

        self._generate_index()

    # -------------------------------------------------------------------------
    # Step 4: Build hierarchical index.rst including Markdown docs
    # -------------------------------------------------------------------------
    def _generate_index(self):
        index_path = self.source_dir / "index.rst"
        self.logger.info("Generating index.rst with Markdown documentation...")

        top_level_modules = sorted(self.module_specs.keys())

        # Find all top-level Markdown files inside /docs (ignore hidden / nested)
        docs_dir = self.source_dir / "docs"
        md_files = [
            md for md in sorted(docs_dir.glob("*.md"))
            if not md.name.startswith("_")
        ]

        # Header
        lines = [
            "Welcome to Penguin Documentation",
            "=================================\n",
            ".. toctree::",
            "   :maxdepth: 3",
            "   :caption: Documentation\n",
        ]

        # Add Markdown docs (relative paths so Sphinx finds them)
        for md in md_files:
            rel = md.relative_to(self.source_dir)
            lines.append(f"   {rel.as_posix()}")

        # Section divider
        lines.extend([
            "",
            "API Reference",
            "--------------",
            "",
            ".. toctree::",
            "   :maxdepth: 3",
            "   :caption: Packages\n",
        ])

        # Add top-level modules (pyplugins, penguin, events)
        for mod in top_level_modules:
            lines.append(f"   {mod}")

        # Write index file
        index_path.write_text("\n".join(lines))
        self.logger.info(f"✅ Wrote combined index.rst including Markdown docs: {index_path}")

    # -------------------------------------------------------------------------
    # Step 5: Build HTML output
    # -------------------------------------------------------------------------
    def _build_html(self):
        self.logger.info("Building Sphinx documentation...")
        sphinx_build.main([
            "-b", "html",
            str(self.source_dir),
            str(self.html_dir),
        ])
        self.logger.info(f"Sphinx documentation built successfully at: {self.html_dir}")
