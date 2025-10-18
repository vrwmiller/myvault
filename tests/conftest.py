"""
Pytest configuration and shared fixtures for getvault tests.

This file contains pytest configuration, shared fixtures, and test utilities
that can be used across multiple test modules.
"""

import pytest
import tempfile
import os
from unittest.mock import Mock


@pytest.fixture
def sample_csv_data():
    """Provide sample CSV data for testing."""
    return b"field1~field2~field3\ntest~value~description\ndb~localhost~database"


@pytest.fixture
def sample_records():
    """Provide sample parsed records for testing."""
    return [
        ["database", "localhost", "Main database server"],
        ["api_key", "abc123", "Production API key"],
        ["Database", "remote.db", "Backup database"],
        ["admin_token", "xyz789", "Admin access token"],
        ["web_api", "def456", "Web service API"]
    ]


@pytest.fixture
def mock_vault_components():
    """Provide mocked Ansible vault components."""
    mock_secret = Mock()
    mock_vault = Mock()
    return mock_secret, mock_vault


@pytest.fixture
def temp_vault_file():
    """Create a temporary file for testing."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.vault') as f:
        f.write(b"mock_encrypted_data")
        temp_path = f.name
    
    yield temp_path
    
    # Cleanup
    try:
        os.unlink(temp_path)
    except FileNotFoundError:
        pass