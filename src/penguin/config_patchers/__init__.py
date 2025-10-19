from .patch_generator import PatchGenerator

__all__ = [
    "PatchGenerator",
]

import importlib
import pkgutil

package = __name__
for _, modname, ispkg in pkgutil.iter_modules(__path__):
    # Skip utility modules that don't define PatchGenerator subclasses
    if not ispkg and modname not in ("patch_generator",):
        module = importlib.import_module(f"{package}.{modname}")
        for attr in dir(module):
            obj = getattr(module, attr)
            try:
                if (
                    isinstance(obj, type)
                    and issubclass(obj, PatchGenerator)
                    and obj is not PatchGenerator
                ):
                    globals()[attr] = obj
                    __all__.append(attr)
            except Exception:
                pass
