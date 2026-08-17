"""Load and run event middlewares from a directory.

Each ``*.py`` file must contain exactly one public function. It receives an
event dictionary and must return the event (possibly changed) to forward it,
or ``None`` to drop it.
"""

from __future__ import annotations

import copy
import importlib.util
import inspect
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Callable, Optional


@dataclass(frozen=True)
class PatchResult:
    event: Optional[dict]
    status: str
    middleware: str = ""


class MiddlewareManager:
    def __init__(self, directory: Path | str = "middlewares") -> None:
        self.directory = Path(directory)
        self._signature = None
        self._middlewares: list[tuple[str, Callable[[dict], Optional[dict]]]] = []

    def _current_signature(self):
        if not self.directory.is_dir():
            return ()
        return tuple(
            (path.name, path.stat().st_mtime_ns, path.stat().st_size)
            for path in sorted(self.directory.glob("*.py"))
            if not path.name.startswith("_")
        )

    def reload_if_changed(self) -> None:
        signature = self._current_signature()
        if signature == self._signature:
            return
        loaded = []
        for filename, _, _ in signature:
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
        print(f"[MIDDLEWARE] Loaded {len(loaded)} script(s) in alphabetical order", flush=True)

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
