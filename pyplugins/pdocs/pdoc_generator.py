'''
This plugin generates our documentation.

It uses pdoc to generate the documentation for the pyplugins module and all its submodules.

It's a bit of a hack, but it works.
'''

import pdoc
from penguin import Plugin
from pathlib import Path


class PdocGenerator(Plugin):
    def __init__(self, panda):
        self.panda = panda
        self.outdir = self.get_arg("outdir")
        self.logger.info("Unloading plugin")
        out_path = Path(self.outdir,"pdoc")
        out_path.mkdir(parents=True, exist_ok=True)

        pdoc.render.configure(
            # docformat="markdown",
            include_undocumented=True,
            template_directory=Path(__file__).parent,
            search=True,
            show_source=True,
        )

        module_list = ["pyplugins", "penguin", "events"]
        modules = {}
        for module_name in pdoc.extract.walk_specs(module_list):
            modules[module_name] = pdoc.doc.Module.from_name(module_name)

        for module in modules.values():
            out = pdoc.render.html_module(module, modules)
            if not out_path:
                return out
            else:
                outfile = out_path / f"{module.fullname.replace('.', '/')}.html"
                outfile.parent.mkdir(parents=True, exist_ok=True)
                outfile.write_bytes(out.encode())

        project_readme = (Path("/docs", "README.md")).read_text()
        index = pdoc.render.env.get_template("index.html.jinja2").render(
            all_modules=modules,
            project_readme=project_readme,
        )
        if index:
            (out_path / "index.html").write_bytes(index.encode())

        search = pdoc.render.search_index(modules)
        if search:
            (out_path / "search.js").write_bytes(search.encode())
        breakpoint()
        assert False, "Pdoc generation complete"
