"""Atomic file output helpers for CyberRecon."""

import os
import tempfile
from contextlib import contextmanager
from pathlib import Path


@contextmanager
def atomic_output(destination):
    destination = Path(destination)
    destination.parent.mkdir(parents=True, exist_ok=True)

    if destination.is_symlink():
        raise ValueError("Output destination cannot be a symlink.")

    descriptor, name = tempfile.mkstemp(
        prefix=".cyberrecon-export-",
        suffix=destination.suffix,
        dir=destination.parent,
    )
    os.close(descriptor)
    temporary = Path(name)

    try:
        yield temporary
        if destination.is_symlink():
            raise ValueError("Output destination cannot be a symlink.")
        temporary.replace(destination)
    finally:
        temporary.unlink(missing_ok=True)
