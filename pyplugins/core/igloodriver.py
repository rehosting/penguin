"""
Plugin to handle interaction from IGLOO driver to report its module base address.
"""

from penguin import plugins, Plugin


class IGLOODriver(Plugin):
    """
    Plugin to handle the IGLOO driver.
    """
    def __init__(self) -> None:
        self.ensure_init = lambda *args: None
        from hyper.consts import igloo_hypercall_constants as iconsts
        self.panda.hypercall(iconsts.IGLOO_MODULE_BASE)(self.hyp_report_igloo_module_baseaddr)

    def hyp_report_igloo_module_baseaddr(self, cpu):
        igloo_test_function = self.panda.arch.get_arg(cpu, 1, convention="syscall")
        addr = plugins.kffi.get_function_address("igloo_test_function")
        offset = igloo_test_function - addr
        self.logger.debug(f"IGLOO module base address reported: {offset:#x}")
        plugins.kffi._fixup_igloo_module_baseaddr(offset)