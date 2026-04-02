"""Configure test imports for the classifinder-engine standalone package.

The engine uses relative imports (from .entropy, from .patterns, etc.),
so we register the engine root as a proper Python package via importlib.
"""

import importlib.util
import sys
from pathlib import Path

engine_root = Path(__file__).resolve().parent.parent

if "classifinder_engine" not in sys.modules:
    spec = importlib.util.spec_from_file_location(
        "classifinder_engine",
        str(engine_root / "__init__.py"),
        submodule_search_locations=[str(engine_root)],
    )
    mod = importlib.util.module_from_spec(spec)
    sys.modules["classifinder_engine"] = mod
    spec.loader.exec_module(mod)
