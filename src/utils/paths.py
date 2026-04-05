"""
Path helpers for resolving project files consistently.
"""

from __future__ import annotations

from pathlib import Path
from typing import Optional, Union


PathLike = Union[str, Path]


def project_root() -> Path:
    """Return the repository root directory."""
    return Path(__file__).resolve().parents[2]


def resolve_project_path(path: PathLike, base_dir: Optional[PathLike] = None) -> Path:
    """
    Resolve a path against common project locations.

    Resolution order for relative paths:
    1. ``base_dir / path`` if ``base_dir`` is provided and exists
    2. ``cwd / path`` if it exists
    3. ``project_root / path``
    4. ``base_dir / path`` if ``base_dir`` is provided, even if it does not exist
    5. ``cwd / path`` as a final fallback
    """
    candidate = Path(path).expanduser()
    raw = str(path).replace("\\", "/")
    if raw.startswith("/app/"):
        rebased = project_root().joinpath(*raw.split("/")[2:])
        if rebased.exists():
            return rebased.resolve()

    if candidate.is_absolute():
        if candidate.exists():
            return candidate
        # Allow local development to reuse container-style /app/... paths by
        # rebasing them onto the repository root when the mounted path is absent.
        parts = candidate.parts
        app_index = next((i for i, part in enumerate(parts) if part.lower() == "app"), None)
        if app_index is not None:
            rebased = project_root().joinpath(*parts[app_index + 1 :])
            if rebased.exists():
                return rebased.resolve()
        return candidate

    if base_dir is not None:
        base_candidate = Path(base_dir).expanduser() / candidate
        if base_candidate.exists():
            return base_candidate.resolve()

    cwd_candidate = Path.cwd() / candidate
    if cwd_candidate.exists():
        return cwd_candidate.resolve()

    repo_candidate = project_root() / candidate
    if repo_candidate.exists():
        return repo_candidate.resolve()

    if base_dir is not None:
        return (Path(base_dir).expanduser() / candidate).resolve()

    return (Path.cwd() / candidate).resolve()
