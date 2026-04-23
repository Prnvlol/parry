"""Configuration loading for Parry — YAML, env vars, and defaults."""

from __future__ import annotations

import json
import logging
import os
from pathlib import Path
from typing import Any

from parry.models import GuardConfig, Mode

logger = logging.getLogger("parry")

CONFIG_FILE_NAMES = [
    "parry.yaml",
    "parry.yml",
    ".parry.yaml",
    ".parry.yml",
]

ENV_PREFIX = "PARRY_"


def load_config(
    config_path: str | Path | None = None,
    **overrides: Any,
) -> GuardConfig:
    """Load guard configuration from file, env vars, and overrides.

    Priority (highest → lowest):
        1. Keyword overrides passed directly
        2. Environment variables (PARRY_MODE, etc.)
        3. Config file (parry.yaml)
        4. Defaults
    """
    data: dict[str, Any] = {}

    # 1. Load from file
    if config_path is not None:
        data = _load_file(Path(config_path))
    else:
        data = _discover_config_file()

    # 2. Apply env var overrides
    _apply_env_vars(data)

    # 3. Apply keyword overrides
    _apply_overrides(data, overrides)

    return GuardConfig.from_dict(data)


def _load_file(path: Path) -> dict[str, Any]:
    """Load a config file (YAML or JSON)."""
    if not path.exists():
        raise FileNotFoundError(f"Parry config file not found: {path}")

    content = path.read_text(encoding="utf-8")

    if path.suffix in (".yaml", ".yml"):
        try:
            import yaml  # type: ignore[import-untyped]
            return yaml.safe_load(content) or {}
        except ImportError:
            logger.warning(
                "PyYAML not installed — cannot load %s. "
                "Install with: pip install parry[full]",
                path,
            )
            return {}
    elif path.suffix == ".json":
        return json.loads(content)  # type: ignore[no-any-return]
    else:
        raise ValueError(f"Unsupported config file format: {path.suffix}")


def _discover_config_file() -> dict[str, Any]:
    """Search for a config file in the current directory."""
    cwd = Path.cwd()
    for name in CONFIG_FILE_NAMES:
        path = cwd / name
        if path.exists():
            # logger.debug("Found config file: %s", path)
            return _load_file(path)
    return {}


def _apply_env_vars(data: dict[str, Any]) -> None:
    """Override config with PARRY_* environment variables."""
    mode = os.environ.get(f"{ENV_PREFIX}MODE")
    if mode:
        data["mode"] = mode

    system_prompt = os.environ.get(f"{ENV_PREFIX}SYSTEM_PROMPT")
    if system_prompt:
        data["system_prompt"] = system_prompt


def _apply_overrides(data: dict[str, Any], overrides: dict[str, Any]) -> None:
    """Apply keyword argument overrides to config data."""
    if "mode" in overrides:
        mode = overrides["mode"]
        if isinstance(mode, Mode):
            data["mode"] = mode.value
        else:
            data["mode"] = mode

    if "system_prompt" in overrides:
        data["system_prompt"] = overrides["system_prompt"]

    if "input" in overrides:
        existing = data.get("input", {})
        if isinstance(overrides["input"], dict):
            existing.update(overrides["input"])
        data["input"] = existing

    if "output" in overrides:
        existing = data.get("output", {})
        if isinstance(overrides["output"], dict):
            existing.update(overrides["output"])
        data["output"] = existing

    if "agents" in overrides:
        existing = data.get("agents", {})
        if isinstance(overrides["agents"], dict):
            existing.update(overrides["agents"])
        data["agents"] = existing
