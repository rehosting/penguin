"""
.. include:: README.md

## Importing in PyPlugins

To import modules in your PyPlugin, you can use the following syntax:
```python
from apis.events import EVENTS
```

Where the `apis` directory exists in the pyplugins directory.

.. include:: ../docs/pyplugin_architecture.md
    :start-after: Plugins are a way to extend the functionality of penguin.
"""

import sys
if "pdoc" in sys.modules:
    import importlib
    import glob
    import os
    from pathlib import Path
    sys.path.append(str(Path(__file__).parent))

    # Import all Python modules in all subdirectories for documentation generation
    base_dir = Path(__file__).parent
    
    # Add the parent directory to sys.path to ensure imports work correctly
    sys.path.insert(0, str(base_dir.parent))
    # Find all Python files (excluding __init__.py files)
    for py_file in glob.glob(str(base_dir / "**" / "*.py"), recursive=True):
        if "__init__.py" in py_file or "__pycache__" in py_file:
            continue


        # Convert file path to module path
        rel_path = os.path.relpath(py_file, str(base_dir.parent))
        module_path = rel_path.replace(os.path.sep, ".")[:-3]  # Remove .py extension
        print(f"Importing {module_path}")
        
        try:
            importlib.import_module(module_path)
        except Exception as e:
            print(f"Error importing {module_path}: {e}")
