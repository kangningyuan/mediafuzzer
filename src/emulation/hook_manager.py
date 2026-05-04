"""Unified hook registration, management, and deregistration."""

import logging
from typing import Any, Callable

logger = logging.getLogger("mediafuzzer.emulation.hooks")


class HookManager:
    """Manages hooks in three categories: coverage, memory_safety, dependency."""

    def __init__(self) -> None:
        self._hooks: dict[str, dict[str, Any]] = {
            "coverage": {},
            "memory_safety": {},
            "dependency": {},
        }

    def register(self, name: str, category: str = "dependency") -> Callable:
        """Decorator for registering a hook function."""
        def decorator(func: Callable) -> Callable:
            self._hooks[category][name] = func
            return func
        return decorator

    def register_hook(self, name: str, hook_func: Any, category: str = "dependency") -> None:
        """Directly register a hook function."""
        self._hooks[category][name] = hook_func

    def register_coverage_hook(self, name: str, hook_func: Any) -> None:
        """Register a coverage hook."""
        self._hooks["coverage"][name] = hook_func

    def register_memory_hook(self, name: str, hook_func: Any) -> None:
        """Register a memory safety hook."""
        self._hooks["memory_safety"][name] = hook_func

    def unregister(self, name: str, category: str) -> None:
        """Remove a specific hook by name and category."""
        self._hooks.get(category, {}).pop(name, None)

    def clear_category(self, category: str) -> None:
        """Remove all hooks in a category."""
        self._hooks.get(category, {}).clear()

    def clear_all(self) -> None:
        """Remove all hooks across all categories."""
        for cat in self._hooks:
            self._hooks[cat].clear()

    def get_all_hooks(self) -> dict[str, dict[str, Any]]:
        """Return a snapshot of all registered hooks."""
        return {cat: dict(hooks) for cat, hooks in self._hooks.items()}

    def get_hooks(self, category: str) -> dict[str, Any]:
        """Return hooks for a specific category."""
        return dict(self._hooks.get(category, {}))

    def has_hook(self, name: str, category: str) -> bool:
        """Check if a hook is registered."""
        return name in self._hooks.get(category, {})

    def get_hook(self, name: str) -> Any | None:
        """Return a hook by name across all categories, or None."""
        for cat in self._hooks:
            if name in self._hooks[cat]:
                return self._hooks[cat][name]
        return None
