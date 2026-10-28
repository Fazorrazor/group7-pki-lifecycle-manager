"""
Pytest fixtures and configuration.
"""

import sys
import os
import pytest

# Ensure src directory is in python search path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "src")))

from pki_lifecycle.database.repository import CertificateRepository


@pytest.fixture
def repo():
    """Provides a clean in-memory database instance for testing."""
    return CertificateRepository()
