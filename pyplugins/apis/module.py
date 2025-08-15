from penguin import Plugin, plugins
from typing import Callable, Optional, List

class Module(Plugin):
    def __init__(self):
        self.ensure_init = lambda *args: None
        self._init_callbacks: List[Callable] = []
        from hyper.consts import igloo_hypercall_constants as iconsts
        self.panda.hypercall(iconsts.IGLOO_MODULE_BASE)(self._hyp_report_igloo_module_baseaddr)
        self._module_init_hyp = plugins.portal.wrap(self._module_init_hyp)
        self.panda.hypercall(iconsts.IGLOO_INIT_MODULE)(self._module_init_hyp)
    
    def _hyp_report_igloo_module_baseaddr(self, cpu):
        igloo_test_function = self.panda.arch.get_arg(cpu, 1, convention="syscall")
        addr = plugins.kffi.get_function_address("igloo_test_function")
        offset = igloo_test_function - addr
        self.logger.debug(f"IGLOO module base address reported: {offset:#x}")
        plugins.kffi._fixup_igloo_module_baseaddr(offset)

    def module_init(self, func: Optional[Callable] = None, **options):
        """
        Decorator for registering module init callbacks.
        Can be used as @plugins.module.module_init or @plugins.module.module_init(...)
        """
        def decorator(f):
            self._init_callbacks.append((f, options))
            return f
        if func is not None:
            return decorator(func)
        return decorator

    def _module_init_hyp(self, cpu):
        """Called when IGLOO_MODULE_INIT hypercall is hit."""
        for cb, opts in self._init_callbacks:
            # If class-level, resolve method
            if hasattr(cb, '__self__') or (hasattr(cb, '__qualname__') and '.' in cb.__qualname__):
                class_name = cb.__qualname__.split('.')[0]
                method_name = cb.__qualname__.split('.')[-1]
                instance = getattr(plugins, class_name, None)
                if instance and hasattr(instance, method_name):
                    bound_cb = getattr(instance, method_name)
                    cb_to_call = bound_cb
                else:
                    self.logger.error(f"Could not resolve class method {cb.__qualname__} for module_init")
                    continue
            else:
                cb_to_call = cb
            # Check argument count
            import inspect
            sig = inspect.signature(cb_to_call)
            params = list(sig.parameters.values())
            # Remove 'self' if present
            if params and params[0].name == 'self':
                params = params[1:]
            if len(params) == 0:
                yield from cb_to_call()
            elif len(params) == 1:
                yield from cb_to_call(cpu)
            else:
                self.logger.error(f"module_init callback {cb_to_call} has unsupported number of arguments: {len(params)}")


