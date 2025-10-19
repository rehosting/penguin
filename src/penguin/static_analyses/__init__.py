import importlib
import pkgutil
from .base import StaticAnalysis

__all__ = []

# Dynamically import all modules and expose their StaticAnalysis subclasses
package = __name__
for _, modname, ispkg in pkgutil.iter_modules(__path__):
    # Skip utility modules that don't define StaticAnalysis subclasses
    if not ispkg and modname not in ("base",):
        module = importlib.import_module(f"{package}.{modname}")
        for attr in dir(module):
            obj = getattr(module, attr)
            try:
                if (
                    isinstance(obj, type)
                    and issubclass(obj, StaticAnalysis)
                    and obj is not StaticAnalysis
                ):
                    globals()[attr] = obj
                    __all__.append(attr)
            except ImportError:
                pass
