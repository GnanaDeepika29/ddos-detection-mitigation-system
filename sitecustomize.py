"""
Interpreter startup compatibility patches for local development.

Python imports ``sitecustomize`` automatically when it is present on
``sys.path``. We use it to smooth over older local dependency versions that
would otherwise prevent framework imports before application code runs.
"""

from __future__ import annotations

import typing_extensions as typing_extensions_module


if not hasattr(typing_extensions_module, "Doc"):
    def _doc_fallback(description: str) -> str:
        return description

    typing_extensions_module.Doc = _doc_fallback
