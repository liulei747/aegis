"""Extraction service: LSP seam, call graph, assembly, packaging.

Owns the heavy, stateful work: a language server process per language, the call
graph walk, reading method bodies, dedupe, and writing the bundle.
"""

from __future__ import annotations

__version__ = "0.1.0"
