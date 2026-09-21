#!/usr/bin/env python3
"""
paths.py — Resource and writable scratch directory resolution.
Stdlib only.
"""
import os
import sys


def engine_dir():
    """Absolute path to the engine directory."""
    override = os.environ.get("AD600_ENGINE_DIR")
    if override and os.path.isdir(override):
        return override
    return os.path.dirname(os.path.abspath(__file__))


def resource_path(name=""):
    """Absolute path to a bundled resource under engine/. Empty name -> engine dir itself."""
    d = engine_dir()
    return d if not name else os.path.join(d, name)


def scratch_dir():
    """Per-user writable working directory for console_cmd.txt / console_out.log."""
    override = os.environ.get("AD600_ENGINE_SCRATCH")
    if override:
        d = override
    else:
        d = os.path.join(os.path.expanduser("~"), ".ad600_scanner")
    try:
        os.makedirs(d, exist_ok=True)
    except Exception:
        d = os.path.join(os.environ.get("TMPDIR", "/tmp"), "ad600_scanner")
        os.makedirs(d, exist_ok=True)
    return d
