"""Load and run event middlewares from a directory.

Each ``*.py`` file must contain exactly one public function. It receives an
event dictionary and must return the event (possibly changed) to forward it,
or ``None`` to drop it.
"""

from __future__ import annotations

import copy
import importlib.util
import inspect
import json
import os
import sys
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Callable, Optional


CONFIG_FILENAME = ".middleware-config.json"


def middleware_directory() -> Path:
    """Return the user-editable middleware directory for this installation."""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent / "middlewares"
    return Path(__file__).resolve().parent / "middlewares"


def read_middleware_config(directory: Path | str) -> dict:
    directory = Path(directory)
    try:
        value = json.loads((directory / CONFIG_FILENAME).read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        return {"order": [], "disabled": []}
    return {
        "order": [name for name in value.get("order", []) if isinstance(name, str)],
        "disabled": [name for name in value.get("disabled", []) if isinstance(name, str)],
    }


def write_middleware_config(directory: Path | str, order: list[str], disabled: list[str]) -> None:
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    target = directory / CONFIG_FILENAME
    temporary = directory / f"{CONFIG_FILENAME}.tmp"
    temporary.write_text(
        json.dumps({"order": order, "disabled": disabled}, indent=2) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, target)


@dataclass(frozen=True)
class PatchResult:
    event: Optional[dict]
    status: str
    middleware: str = ""


class MiddlewareManager:
    def __init__(self, directory: Path | str | None = None) -> None:
        self.directory = Path(directory) if directory is not None else middleware_directory()
        self._signature = None
        self._middlewares: list[tuple[str, Callable[[dict], Optional[dict]]]] = []

    def _current_signature(self):
        if not self.directory.is_dir():
            return (), None
        files = tuple(
            (path.name, path.stat().st_mtime_ns, path.stat().st_size)
            for path in sorted(self.directory.glob("*.py"))
            if not path.name.startswith("_")
        )
        config = self.directory / CONFIG_FILENAME
        config_signature = None
        if config.is_file():
            stat = config.stat()
            config_signature = (stat.st_mtime_ns, stat.st_size)
        return files, config_signature

    def reload_if_changed(self) -> None:
        signature = self._current_signature()
        if signature == self._signature:
            return
        loaded = []
        files = {filename: (mtime, size) for filename, mtime, size in signature[0]}
        config = read_middleware_config(self.directory)
        disabled = set(config["disabled"])
        ordered_names = [name for name in config["order"] if name in files]
        ordered_names.extend(sorted(set(files) - set(ordered_names)))
        for filename in ordered_names:
            if filename in disabled:
                continue
            path = self.directory / filename
            try:
                spec = importlib.util.spec_from_file_location(
                    f"netcheat_middleware_{path.stem}_{path.stat().st_mtime_ns}", path
                )
                if spec is None or spec.loader is None:
                    raise ImportError("could not create module spec")
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                functions = self._public_functions(module)
                if len(functions) != 1:
                    raise ValueError("script must define exactly one public function")
                loaded.append((path.name, functions[0]))
            except Exception as exc:
                print(f"[MIDDLEWARE] Failed to load {path}: {exc}", flush=True)
        self._middlewares = loaded
        self._signature = signature
        print(f"[MIDDLEWARE] Loaded {len(loaded)} enabled script(s) in configured order", flush=True)

    @staticmethod
    def _public_functions(module: ModuleType):
        return [
            value
            for name, value in vars(module).items()
            if not name.startswith("_")
            and inspect.isfunction(value)
            and value.__module__ == module.__name__
        ]

    def apply(self, event: dict) -> PatchResult:
        self.reload_if_changed()
        current = copy.deepcopy(event)
        original = copy.deepcopy(event)
        changed_by = []
        for name, middleware in self._middlewares:
            try:
                result = middleware(current)
            except Exception as exc:
                print(f"[MIDDLEWARE] {name} failed: {exc}", flush=True)
                continue
            if result is None:
                return PatchResult(None, "blocked by middleware", name)
            if not isinstance(result, dict):
                print(f"[MIDDLEWARE] {name} returned {type(result).__name__}; ignored", flush=True)
                continue
            if result != current:
                changed_by.append(name)
            current = result
        if current != original:
            return PatchResult(current, "changed by middleware", ", ".join(changed_by))
        return PatchResult(current, "captured")
