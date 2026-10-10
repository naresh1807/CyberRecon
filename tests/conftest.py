import os
from pathlib import Path
import pytest
os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")

@pytest.fixture
def examples():
    return Path(__file__).resolve().parents[1] / "examples"
