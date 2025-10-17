import importlib
import pkgutil
import sys

__all__ = []

# Dynamically import all modules and expose their StaticAnalysis subclasses
package = __name__
for _, modname, ispkg in pkgutil.iter_modules(__path__):
    if not ispkg:
        module = importlib.import_module(f"{package}.{modname}")
        for attr in dir(module):
            obj = getattr(module, attr)
            # Check for StaticAnalysis subclasses (excluding the base class itself)
            try:
                from .base import StaticAnalysis
                if (
                    isinstance(obj, type)
                    and issubclass(obj, StaticAnalysis)
                    and obj is not StaticAnalysis
                ):
                    globals()[attr] = obj
                    __all__.append(attr)
            except ImportError:
                pass
