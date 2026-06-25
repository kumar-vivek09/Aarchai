"""Auto-discover and load tool plugins from the plugins/ directory."""
from __future__ import annotations
import importlib
import importlib.util
import sys
from pathlib import Path

PLUGINS_DIR = Path(__file__).parent

_registry: dict[str, list] = {
    "stage1": [], "stage2": [], "stage3": [],
    "stage4": [], "stage5": [], "stage6": [],
}


def load_plugins():
    """Scan plugins/ directory and register all valid plugins."""
    for py_file in PLUGINS_DIR.glob("*.py"):
        if py_file.name in ("__init__.py", "loader.py"):
            continue
        try:
            spec   = importlib.util.spec_from_file_location(py_file.stem, py_file)
            module = importlib.util.module_from_spec(spec)
            spec.loader.exec_module(module)

            stage = getattr(module, "STAGE", None)
            name  = getattr(module, "TOOL_NAME", py_file.stem)
            run_fn = getattr(module, "run", None)

            if stage and run_fn:
                key = f"stage{stage}"
                if key in _registry:
                    _registry[key].append({"name": name, "run": run_fn, "module": module})
                    print(f"  [plugin] Loaded: {name} → {key}")
        except Exception as e:
            print(f"  [plugin] Failed to load {py_file.name}: {e}")


def get_plugins(stage_num: str | int) -> list[dict]:
    """Return all plugins registered for a given stage number."""
    return _registry.get(f"stage{stage_num}", [])
