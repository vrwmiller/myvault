"""
Pytest configuration and shared fixtures for myvault tests.

This file contains pytest configuration, shared fixtures, and test utilities
that can be used across multiple test modules.
"""

import json
import os
import stat
import tempfile

import pytest
from unittest.mock import Mock


@pytest.fixture
def sample_vault_entries():
    """Provide sample vault entries matching the JSON vault schema."""
    return [
        {"property": "website1.com", "username": "user@example.com", "password": "secret123"},
        {"property": "api.service", "username": "apiuser", "password": "apipass", "apitoken": "tok_abc123"},
        {"property": "database.server", "username": "dbadmin", "password": "dbpass789", "notes": "Production DB"},
        {"property": "admin.portal", "username": "admin", "password": "adminpass"},
        {"property": "web.api", "username": "webuser", "password": "webpass456"},
    ]


@pytest.fixture
def sample_vault_entry():
    """Provide a single sample vault entry."""
    return {"property": "website1.com", "username": "user@example.com", "password": "secret123"}


@pytest.fixture
def mock_vault_components():
    """Provide mocked Ansible vault components."""
    mock_secret = Mock()
    mock_vault = Mock()
    return mock_secret, mock_vault


@pytest.fixture
def temp_vault_file():
    """Create a temporary encrypted vault file for testing."""
    with tempfile.NamedTemporaryFile(mode='wb', delete=False, suffix='.vault') as f:
        f.write(b"mock_encrypted_data")
        temp_path = f.name
    os.chmod(temp_path, stat.S_IRUSR | stat.S_IWUSR)

    yield temp_path

    try:
        os.unlink(temp_path)
    except FileNotFoundError:
        pass


@pytest.fixture
def temp_json_input_file(sample_vault_entries, tmp_path):
    """Create a temporary JSON input file with secure permissions."""
    json_file = tmp_path / "input.json"
    json_file.write_text(json.dumps(sample_vault_entries, indent=2))
    json_file.chmod(0o600)
    return str(json_file)