"""Integration test plugin for the guest ``penguest`` binding.

The guest driver ``/tests/penguest.py`` runs under the staged in-guest CPython
(``/igloo/utils/python3``), ``import penguest``, and calls
``penguest.portal_call(PENGUEST_TEST_MAGIC, ...)`` plus ``penguest.log`` /
``penguest.report``. This plugin is the host handler for the test magic: it
checks the args and writes ``penguest_test.txt`` for the verifier. The log side
is verified separately via the ``penguest`` host bridge's
``<outdir>/penguest_guest.log``.

See ``tests/integration/test_target/patches/tests/penguest.yaml``.
"""

from os.path import join

from penguin import Plugin, plugins

# Must match /tests/penguest.py in the penguest.yaml test patch.
PENGUEST_TEST_MAGIC = 0x70677401  # 'pgt' + 1
PENGUEST_ARG1 = 0xDEADBEEFF1F1F1F1
PENGUEST_ARG2 = 0x1337C0DEFEEDC0DE


class PenguestTest(Plugin):
    """Host handler proving a guest Python script reaches the host via penguest."""

    def __init__(self):
        self.outdir = self.get_arg("outdir")
        self.reported = False

    @plugins.portalcall.portalcall(PENGUEST_TEST_MAGIC)
    def _on_test(self, a1, a2):
        return self.handle_test(a1, a2)

    def handle_test(self, a1, a2):
        ok = (a1 == PENGUEST_ARG1 and a2 == PENGUEST_ARG2)
        if not ok:
            self.logger.error(
                f"PENGUEST test failed: a1={a1:#x} (want {PENGUEST_ARG1:#x}), "
                f"a2={a2:#x} (want {PENGUEST_ARG2:#x})")
        self._report(ok)
        return 13

    def _report(self, ok):
        if self.reported:
            return
        self.reported = True
        res = "passed" if ok else "failed"
        self.logger.info(f"PENGUEST test: {res}")
        with open(join(self.outdir, "penguest_test.txt"), "w") as f:
            f.write(f"PENGUEST test: {res}\n")

    def uninit(self):
        # If the guest never made the call, record a failure so the verifier
        # doesn't hang on a missing file.
        self._report(False)
