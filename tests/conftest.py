import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from deid.masking import KeyRing


@pytest.fixture
def keyring():
    return KeyRing.from_string("unit-test-secret-key-0123456789-abcdefghijkl")
