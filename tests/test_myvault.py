#!/usr/bin/env python3
"""
Tests for myvault.py - JSON-based Ansible Vault Secret Manager

Comprehensive test suite covering all subcommands, error cases, and security scenarios.
"""

import os
import sys
import json
import tempfile
import shutil
import stat
import platform
from contextlib import contextmanager
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open, call
import pytest

# Add the parent directory to sys.path to import myvault

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import myvault
from myvault import VaultError, JSONValidator, VaultManager, match_property_expression

class TestPropertyExpressions:
    """Test property expression matching functionality."""
    
    def test_match_exact_property(self):
        """Test exact property matching."""
        assert match_property_expression("website1.com", "website1.com")
        assert not match_property_expression("website1.com", "website2.com")
    
    def test_match_case_insensitive(self):
        """Test case insensitive matching."""
        assert match_property_expression("Website1.Com", "website1.com")
        assert match_property_expression("website1.com", "WEBSITE1.COM")
    
    def test_match_glob_patterns(self):
        """Test glob pattern matching."""
        # Wildcard patterns
        assert match_property_expression("website1.com", "web*")
        assert match_property_expression("website1.com", "*.com")
        assert match_property_expression("website1.com", "*site*")
        
        # Question mark patterns
        assert match_property_expression("web1.com", "web?.com")
        assert not match_property_expression("web123.com", "web?.com")
        
        # Character class patterns
        assert match_property_expression("web1.com", "web[0-9].com")
        assert not match_property_expression("weba.com", "web[0-9].com")
    
    def test_match_pipe_separated_alternatives(self):
        """Test pipe-separated alternative matching."""
        expression = "website1.com|website2.com|api.service"
        
        assert match_property_expression("website1.com", expression)
        assert match_property_expression("website2.com", expression)
        assert match_property_expression("api.service", expression)
        assert not match_property_expression("database.server", expression)
    
    def test_match_pipe_with_globs(self):
        """Test pipe-separated alternatives with glob patterns."""
        expression = "web*|*api*|database.*"
        
        assert match_property_expression("website1.com", expression)
        assert match_property_expression("web2.net", expression)
        assert match_property_expression("api.service", expression)
        assert match_property_expression("myapi.server", expression)
        assert match_property_expression("database.prod", expression)
        assert not match_property_expression("ftp.server", expression)
    
    def test_match_empty_inputs(self):
        """Test edge cases with empty inputs."""
        assert not match_property_expression("", "pattern")
        assert not match_property_expression("property", "")
        assert not match_property_expression("", "")
    
    def test_match_whitespace_handling(self):
        """Test whitespace handling in expressions."""
        expression = " web* | *api* | database.* "
        
        assert match_property_expression("website1.com", expression)
        assert match_property_expression("api.service", expression)
        assert match_property_expression("database.prod", expression)


class TestJSONValidator:
    """Test the JSONValidator class."""
    
    def test_validate_file_permissions_secure(self, tmp_path):
        """Test that secure file permissions (600) are accepted."""
        test_file = tmp_path / "secure.json"
        test_file.write_text('{"test": "data"}')
        test_file.chmod(0o600)
        
        # Should not raise an exception
        JSONValidator.validate_file_permissions(str(test_file))
    
    def test_validate_file_permissions_insecure(self, tmp_path):
        """Test that insecure file permissions raise an error."""
        test_file = tmp_path / "insecure.json"
        test_file.write_text('{"test": "data"}')
        test_file.chmod(0o644)  # World readable
        
        with pytest.raises(VaultError, match="Insecure file permissions"):
            JSONValidator.validate_file_permissions(str(test_file))
    
    def test_validate_file_permissions_nonexistent(self):
        """Test that nonexistent files don't raise an error."""
        # Should not raise an exception
        JSONValidator.validate_file_permissions("/nonexistent/file.json")
    
    def test_validate_json_structure_list(self):
        """Test validation of list format JSON."""
        data = [
            {"property": "test1", "username": "user1"},
            {"property": "test2", "password": "pass2"}
        ]
        
        result = JSONValidator.validate_json_structure(data)
        assert len(result) == 2
        assert result[0]["property"] == "test1"
        assert result[1]["property"] == "test2"
    
    def test_validate_json_structure_single_object(self):
        """Test validation of single object format JSON."""
        data = {"property": "test1", "username": "user1"}
        
        result = JSONValidator.validate_json_structure(data)
        assert len(result) == 1
        assert result[0]["property"] == "test1"
    
    def test_validate_json_structure_missing_property(self):
        """Test validation fails when required property field is missing."""
        data = [{"username": "user1", "password": "pass1"}]
        
        with pytest.raises(VaultError, match="missing required field: property"):
            JSONValidator.validate_json_structure(data)
    
    def test_validate_json_structure_empty_property(self):
        """Test validation fails when property field is empty."""
        data = [{"property": "", "username": "user1"}]
        
        with pytest.raises(VaultError, match="empty property field"):
            JSONValidator.validate_json_structure(data)
    
    def test_validate_json_structure_invalid_type(self):
        """Test validation fails for invalid data types."""
        data = "not a list or dict"
        
        with pytest.raises(VaultError, match="must be a list of objects"):
            JSONValidator.validate_json_structure(data)


class TestVaultManager:
    """Test the VaultManager class."""
    
    @pytest.fixture
    def vault_manager(self):
        """Create a VaultManager instance for testing."""
        return VaultManager("test_password")
    
    def test_init(self, vault_manager):
        """Test VaultManager initialization."""
        assert vault_manager.secret is not None
        assert vault_manager.vault is not None
    
    @patch('myvault.VaultLib')
    def test_encrypt_data(self, mock_vault_lib, vault_manager):
        """Test data encryption."""
        mock_vault = MagicMock()
        mock_vault.encrypt.return_value = b"encrypted_data"
        vault_manager.vault = mock_vault
        
        data = [{"property": "test", "password": "secret"}]
        result = vault_manager.encrypt_data(data)
        
        assert result == b"encrypted_data"
        mock_vault.encrypt.assert_called_once()
    
    @patch('myvault.VaultLib')
    def test_encrypt_data_error(self, mock_vault_lib, vault_manager):
        """Test encryption error handling."""
        mock_vault = MagicMock()
        mock_vault.encrypt.side_effect = Exception("Encryption failed")
        vault_manager.vault = mock_vault
        
        data = [{"property": "test", "password": "secret"}]
        
        with pytest.raises(VaultError, match="Failed to encrypt data"):
            vault_manager.encrypt_data(data)
    
    @patch('myvault.VaultLib')
    def test_decrypt_data(self, mock_vault_lib, vault_manager):
        """Test data decryption."""
        mock_vault = MagicMock()
        test_data = [{"property": "test", "password": "secret"}]
        mock_vault.decrypt.return_value = json.dumps(test_data).encode('utf-8')
        vault_manager.vault = mock_vault
        
        result = vault_manager.decrypt_data(b"encrypted_data")
        
        assert result == test_data
        mock_vault.decrypt.assert_called_once_with(b"encrypted_data")
    
    @patch('myvault.VaultLib')
    def test_decrypt_data_single_object(self, mock_vault_lib, vault_manager):
        """Test decryption of single object format."""
        mock_vault = MagicMock()
        test_data = {"property": "test", "password": "secret"}
        mock_vault.decrypt.return_value = json.dumps(test_data).encode('utf-8')
        vault_manager.vault = mock_vault
        
        result = vault_manager.decrypt_data(b"encrypted_data")
        
        assert len(result) == 1
        assert result[0] == test_data
    
    @patch('myvault.VaultLib')
    def test_decrypt_data_json_error(self, mock_vault_lib, vault_manager):
        """Test decryption with invalid JSON."""
        mock_vault = MagicMock()
        mock_vault.decrypt.return_value = b"invalid json"
        vault_manager.vault = mock_vault
        
        with pytest.raises(VaultError, match="Invalid JSON in vault file"):
            vault_manager.decrypt_data(b"encrypted_data")
    
    @patch('myvault.VaultLib')
    def test_decrypt_data_vault_error(self, mock_vault_lib, vault_manager):
        """Test decryption vault error handling."""
        mock_vault = MagicMock()
        mock_vault.decrypt.side_effect = Exception("Decryption failed")
        vault_manager.vault = mock_vault
        
        with pytest.raises(VaultError, match="Failed to decrypt data"):
            vault_manager.decrypt_data(b"encrypted_data")
    
    def test_load_vault_file_nonexistent(self, vault_manager, tmp_path):
        """Test loading nonexistent vault file."""
        nonexistent_file = tmp_path / "nonexistent.json"
        result = vault_manager.load_vault_file(str(nonexistent_file))
        assert result == []
    
    def test_load_vault_file_empty(self, vault_manager, tmp_path):
        """Test loading empty vault file."""
        empty_file = tmp_path / "empty.json"
        empty_file.write_bytes(b"")
        
        result = vault_manager.load_vault_file(str(empty_file))
        assert result == []
    
    @patch('myvault.VaultManager.decrypt_data')
    def test_load_vault_file_success(self, mock_decrypt, vault_manager, tmp_path):
        """Test successful vault file loading."""
        test_data = [{"property": "test", "password": "secret"}]
        mock_decrypt.return_value = test_data
        
        vault_file = tmp_path / "vault.json"
        vault_file.write_bytes(b"encrypted_content")
        
        result = vault_manager.load_vault_file(str(vault_file))
        assert result == test_data
        mock_decrypt.assert_called_once_with(b"encrypted_content")
    
    @patch('myvault.VaultManager.encrypt_data')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_save_vault_file(self, mock_validate, mock_encrypt, vault_manager, tmp_path):
        """Test successful vault file saving."""
        mock_encrypt.return_value = b"encrypted_data"
        
        test_data = [{"property": "test", "password": "secret"}]
        vault_file = tmp_path / "vault.json"
        
        vault_manager.save_vault_file(str(vault_file), test_data)
        
        # Check file was created and has correct content
        assert vault_file.exists()
        assert vault_file.read_bytes() == b"encrypted_data"
        
        # Check permissions were validated
        mock_validate.assert_called_once_with(str(vault_file))
        mock_encrypt.assert_called_once_with(test_data)


class TestCommandHandlers:
    """Test the command handler functions."""
    
    @pytest.fixture
    def sample_json_file(self, tmp_path):
        """Create a sample JSON file for testing."""
        test_data = [
            {"property": "test1.com", "username": "user1", "password": "pass1"},
            {"property": "test2.com", "username": "user2", "password": "pass2"}
        ]
        
        json_file = tmp_path / "test.json"
        json_file.write_text(json.dumps(test_data, indent=2))
        json_file.chmod(0o600)
        
        return str(json_file)
    
    def test_handle_validate_success(self, sample_json_file, capsys):
        """Test successful validation."""
        args = MagicMock()
        args.input = sample_json_file
        
        myvault.handle_validate(args)
        
        captured = capsys.readouterr()
        assert "JSON validation completed successfully!" in captured.out
    
    def test_handle_validate_file_not_found(self):
        """Test validation with nonexistent file."""
        args = MagicMock()
        args.input = "/nonexistent/file.json"
        
        with pytest.raises(VaultError, match="Input file not found"):
            myvault.handle_validate(args)
    
    def test_handle_validate_invalid_json(self, tmp_path):
        """Test validation with invalid JSON."""
        invalid_file = tmp_path / "invalid.json"
        invalid_file.write_text("invalid json content")
        invalid_file.chmod(0o600)
        
        args = MagicMock()
        args.input = str(invalid_file)
        
        with pytest.raises(VaultError, match="Invalid JSON syntax"):
            myvault.handle_validate(args)
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_read_success(self, mock_validate, mock_vault_class, capsys):
        """Test successful read operation."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "test.com", "username": "user", "password": "secret"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = None
        args.output = None
        
        myvault.handle_read(args, "password")
        
        captured = capsys.readouterr()
        assert "test.com" in captured.out
        assert "secret" in captured.out  # Passwords should be unmasked in read mode
    
    @patch('myvault.VaultManager')
    def test_handle_read_no_file(self, mock_vault_class):
        """Test read without specifying vault file."""
        args = MagicMock()
        args.file = None
        
        with pytest.raises(VaultError, match="Vault file.*is required"):
            myvault.handle_read(args, "password")
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_read_empty_vault(self, mock_validate, mock_vault_class, capsys):
        """Test read with empty vault."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = []
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = None
        args.output = None
        
        myvault.handle_read(args, "password")
        
        captured = capsys.readouterr()
        assert "No entries found" in captured.out
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_read_with_property_filter(self, mock_validate, mock_vault_class, capsys):
        """Test read with property filtering."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "test1.com", "username": "user1"},
            {"property": "test2.com", "username": "user2"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "test1.com"
        args.output = None
        
        myvault.handle_read(args, "password")
        
        captured = capsys.readouterr()
        assert "test1.com" in captured.out
        assert "test2.com" not in captured.out
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_read_property_not_found(self, mock_validate, mock_vault_class, capsys):
        """Test read with nonexistent property."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "test.com", "username": "user"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "nonexistent.com"
        args.output = None
        
        myvault.handle_read(args, "password")
        
        captured = capsys.readouterr()
        assert "No entries found matching property expression: nonexistent.com" in captured.out
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_read_with_glob_expressions(self, mock_validate, mock_vault_class, capsys):
        """Test read with glob pattern expressions."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1", "password": "secret1"},
            {"property": "website2.com", "username": "user2", "password": "secret2"},
            {"property": "api.service", "username": "api", "password": "token"},
            {"property": "database.server", "username": "db", "password": "dbpass"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "web*"
        args.output = None
        
        myvault.handle_read(args, "password")
        
        captured = capsys.readouterr()
        # Should match both website1.com and website2.com  
        assert "website1.com" in captured.out
        assert "website2.com" in captured.out
        assert "api.service" not in captured.out
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_read_with_pipe_expressions(self, mock_validate, mock_vault_class, capsys):
        """Test read with pipe-separated expressions."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1", "password": "secret1"},
            {"property": "api.service", "username": "api", "password": "token"},
            {"property": "database.server", "username": "db", "password": "dbpass"},
            {"property": "ftp.server", "username": "ftp", "password": "ftppass"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "website1.com|api.service|database.*"
        args.output = None
        
        myvault.handle_read(args, "password")
        
        captured = capsys.readouterr()
        # Should match website1.com, api.service, and database.server
        assert "website1.com" in captured.out
        assert "api.service" in captured.out
        assert "database.server" in captured.out
        assert "ftp.server" not in captured.out
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_read_expression_no_matches(self, mock_validate, mock_vault_class, capsys):
        """Test read with expression that matches nothing."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1"},
            {"property": "api.service", "username": "api"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "nonexistent*|missing.*"
        args.output = None
        
        myvault.handle_read(args, "password")
        
        captured = capsys.readouterr()
        assert "No entries found matching property expression: nonexistent*|missing.*" in captured.out

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_read_format_json(self, mock_validate, mock_vault_class, capsys):
        """Test read with --format json outputs a JSON array to stdout."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1", "password": "secret1"},
            {"property": "api.service", "username": "api", "password": "token"},
        ]
        mock_vault_class.return_value = mock_vault

        args = MagicMock()
        args.file = "vault.json"
        args.property = None
        args.output = None
        args.output_format = "json"

        myvault.handle_read(args, "password")

        captured = capsys.readouterr()
        parsed = json.loads(captured.out)
        assert isinstance(parsed, list)
        assert len(parsed) == 2
        assert parsed[0]["property"] == "website1.com"

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_read_format_raw(self, mock_validate, mock_vault_class, capsys):
        """Test read with --format raw --field outputs one value per entry."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1", "password": "secret1"},
            {"property": "api.service", "username": "api", "password": "token"},
        ]
        mock_vault_class.return_value = mock_vault

        args = MagicMock()
        args.file = "vault.json"
        args.property = None
        args.output = None
        args.output_format = "raw"
        args.field = "password"

        myvault.handle_read(args, "password")

        captured = capsys.readouterr()
        lines = captured.out.strip().splitlines()
        assert lines == ["secret1", "token"]

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_read_format_raw_missing_field_arg(self, mock_validate, mock_vault_class):
        """Test read with --format raw but no --field raises VaultError."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1", "password": "secret1"},
        ]
        mock_vault_class.return_value = mock_vault

        args = MagicMock()
        args.file = "vault.json"
        args.property = None
        args.output = None
        args.output_format = "raw"
        args.field = None

        with pytest.raises(VaultError, match="--field is required"):
            myvault.handle_read(args, "password")

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_read_format_raw_field_missing_from_entry(self, mock_validate, mock_vault_class, capsys):
        """Test raw format when the requested field is absent from an entry writes to stderr."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1"},
        ]
        mock_vault_class.return_value = mock_vault

        args = MagicMock()
        args.file = "vault.json"
        args.property = None
        args.output = None
        args.output_format = "raw"
        args.field = "password"

        myvault.handle_read(args, "password")

        captured = capsys.readouterr()
        assert "not found" in captured.err
        assert captured.out.strip() == ""

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_read_format_pipe_is_default(self, mock_validate, mock_vault_class, capsys):
        """Test that pipe format (default) still produces pipe-separated output."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1", "password": "secret1"},
        ]
        mock_vault_class.return_value = mock_vault

        args = MagicMock()
        args.file = "vault.json"
        args.property = None
        args.output = None
        args.output_format = "pipe"

        myvault.handle_read(args, "password")

        captured = capsys.readouterr()
        assert "website1.com | user1 | secret1" in captured.out

    @patch.dict(os.environ, {'VAULT_PASSWORD': 'test_password'})
    @patch('myvault.handle_read')
    def test_main_read_format_json_routed(self, mock_handle):
        """Test that --format json is passed through to handle_read."""
        with patch('sys.argv', ['myvault.py', '-f', 'vault.json', 'read', '--format', 'json']):
            myvault.main()
        mock_handle.assert_called_once()
        call_args = mock_handle.call_args[0][0]
        assert call_args.output_format == 'json'

    @patch.dict(os.environ, {'VAULT_PASSWORD': 'test_password'})
    @patch('myvault.handle_read')
    def test_main_read_format_raw_and_field_routed(self, mock_handle):
        """Test that --format raw --field is passed through to handle_read."""
        with patch('sys.argv', ['myvault.py', '-f', 'vault.json', 'read',
                                '--format', 'raw', '--field', 'password']):
            myvault.main()
        mock_handle.assert_called_once()
        call_args = mock_handle.call_args[0][0]
        assert call_args.output_format == 'raw'
        assert call_args.field == 'password'

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('builtins.input', return_value='y')
    def test_handle_delete_with_expressions_single_match(self, mock_input, mock_validate, mock_vault_class, capsys):
        """Test delete with expression that matches single entry."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1", "password": "secret1"},
            {"property": "api.service", "username": "api", "password": "token"},
            {"property": "database.server", "username": "db", "password": "dbpass"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "website1.com"
        args.force = False
        
        myvault.handle_delete(args, "password")
        
        captured = capsys.readouterr()
        assert "Found 1 entries matching expression" in captured.out
        assert "website1.com" in captured.out
        # With mocked input returning 'y', the deletion should complete
        assert "Successfully deleted 1 entries" in captured.out
        mock_vault.save_vault_file.assert_called_once()
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('builtins.input', return_value='y')
    def test_handle_delete_with_expressions_multiple_matches(self, mock_input, mock_validate, mock_vault_class, capsys):
        """Test delete with expression that matches multiple entries."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1", "password": "secret1"},
            {"property": "website2.com", "username": "user2", "password": "secret2"},
            {"property": "api.service", "username": "api", "password": "token"},
            {"property": "database.server", "username": "db", "password": "dbpass"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "web*"
        args.force = False
        
        myvault.handle_delete(args, "password")
        
        captured = capsys.readouterr()
        assert "Found 2 entries matching expression 'web*'" in captured.out
        assert "website1.com" in captured.out
        assert "website2.com" in captured.out
        # With mocked input returning 'y', the deletion should complete
        assert "Successfully deleted 2 entries" in captured.out
        mock_vault.save_vault_file.assert_called_once()
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_delete_with_expressions_force_mode(self, mock_validate, mock_vault_class, capsys):
        """Test delete with expression in force mode (no confirmation)."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "test1.old", "username": "user1"},
            {"property": "test2.old", "username": "user2"},
            {"property": "production.com", "username": "prod"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "*.old"
        args.force = True
        
        myvault.handle_delete(args, "password")
        
        captured = capsys.readouterr()
        assert "Force mode: Deleting 2 entries matching expression '*.old'" in captured.out
        assert "test1.old" in captured.out
        assert "test2.old" in captured.out
        # Should not prompt for confirmation in force mode
        assert "Delete all" not in captured.out
        mock_vault.save_vault_file.assert_called_once()
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('builtins.input', side_effect=['n', 'n'])  # Skip both entries
    def test_handle_delete_with_expressions_cancelled(self, mock_input, mock_validate, mock_vault_class, capsys):
        """Test delete with expression cancelled by user."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1"},
            {"property": "website2.com", "username": "user2"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "web*"
        args.force = False
        
        myvault.handle_delete(args, "password")
        
        captured = capsys.readouterr()
        assert "No entries selected for deletion" in captured.out
        # Should not save if cancelled
        mock_vault.save_vault_file.assert_not_called()
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('builtins.input', side_effect=['y', 'n', 'y'])  # Select 1st, skip 2nd, confirm final
    def test_handle_delete_with_expressions_partial_selection(self, mock_input, mock_validate, mock_vault_class, capsys):
        """Test delete with expression where user selects some entries."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1"},
            {"property": "website2.com", "username": "user2"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "web*"
        args.force = False
        
        myvault.handle_delete(args, "password")
        
        captured = capsys.readouterr()
        assert "✓ Marked for deletion" in captured.out
        assert "✗ Skipped" in captured.out
        assert "Summary: 1 of 2 entries marked for deletion" in captured.out
        # Should save since user confirmed final deletion
        mock_vault.save_vault_file.assert_called_once()
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('builtins.input', side_effect=['q'])  # Quit on first entry
    def test_handle_delete_with_expressions_quit(self, mock_input, mock_validate, mock_vault_class, capsys):
        """Test delete with expression where user quits early."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1"},
            {"property": "website2.com", "username": "user2"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "web*"
        args.force = False
        
        myvault.handle_delete(args, "password")
        
        captured = capsys.readouterr()
        assert "Delete operation cancelled" in captured.out
        # Should not save if user quit
        mock_vault.save_vault_file.assert_not_called()

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_delete_expression_no_matches(self, mock_validate, mock_vault_class, capsys):
        """Test delete with expression that matches nothing."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "website1.com", "username": "user1"},
            {"property": "api.service", "username": "api"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "nonexistent*|missing.*"
        args.force = False
        
        myvault.handle_delete(args, "password")
        
        captured = capsys.readouterr()
        assert "No entries found matching property expression: nonexistent*|missing.*" in captured.out
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('builtins.input', return_value='y')
    def test_handle_create_with_conflicts(self, mock_input, mock_validate, mock_vault_class, sample_json_file, capsys):
        """Test create with property conflicts."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "test1.com", "username": "existing"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.input = sample_json_file
        
        myvault.handle_create(args, "password")
        
        captured = capsys.readouterr()
        assert "Successfully created" in captured.out
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('builtins.input', return_value='n')
    def test_handle_create_conflicts_cancelled(self, mock_input, mock_validate, mock_vault_class, sample_json_file):
        """Test create cancelled due to conflicts."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "test1.com", "username": "existing"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.input = sample_json_file
        
        myvault.handle_create(args, "password")
        # Should return without error (operation cancelled)
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('builtins.input', return_value='y')
    def test_handle_update_success(self, mock_input, mock_validate, mock_vault_class, sample_json_file, capsys):
        """Test successful update operation."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "test1.com", "username": "old_user", "password": "old_pass"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.input = sample_json_file
        
        myvault.handle_update(args, "password")
        
        captured = capsys.readouterr()
        assert "Successfully updated" in captured.out
    
    @patch('myvault.VaultManager')
    def test_handle_update_empty_vault(self, mock_vault_class, sample_json_file):
        """Test update with empty vault."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = []
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.input = sample_json_file
        
        with pytest.raises(VaultError, match="No existing entries found"):
            myvault.handle_update(args, "password")
    
    @patch('myvault.VaultManager')
    @patch('builtins.input', return_value='y')
    def test_handle_delete_success(self, mock_input, mock_vault_class, capsys):
        """Test successful delete operation."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "test.com", "username": "user", "password": "secret"},
            {"property": "test2.com", "username": "user2"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "test.com"
        args.force = False
        
        myvault.handle_delete(args, "password")
        
        captured = capsys.readouterr()
        assert "Successfully deleted 1 entries" in captured.out
        # Should save remaining entries, not remove file
        mock_vault.save_vault_file.assert_called_once()
    
    @patch('myvault.VaultManager')
    def test_handle_delete_force(self, mock_vault_class):
        """Test delete with force flag."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "test.com", "username": "user"},
            {"property": "test2.com", "username": "user2"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "test.com"
        args.force = True
        
        # Should complete without prompting
        myvault.handle_delete(args, "password")
        # Should save remaining entries
        mock_vault.save_vault_file.assert_called_once()
    
    @patch('myvault.VaultManager')
    def test_handle_delete_property_not_found(self, mock_vault_class, capsys):
        """Test delete with nonexistent property."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "test.com", "username": "user"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "nonexistent.com"
        args.force = False
        
        myvault.handle_delete(args, "password")
        
        captured = capsys.readouterr()
        assert "No entries found matching property expression: nonexistent.com" in captured.out
    
    @patch('myvault.VaultManager')
    @patch('os.remove')
    def test_handle_delete_last_entry(self, mock_remove, mock_vault_class, capsys):
        """Test delete of last entry removes vault file."""
        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = [
            {"property": "test.com", "username": "user"}
        ]
        mock_vault_class.return_value = mock_vault
        
        args = MagicMock()
        args.file = "vault.json"
        args.property = "test.com"
        args.force = True
        
        myvault.handle_delete(args, "password")
        
        captured = capsys.readouterr()
        assert "Vault file removed" in captured.out
        mock_remove.assert_called_once_with("vault.json")


class TestMainFunction:
    """Test the main function and argument parsing."""
    
    def test_main_no_command(self, capsys):
        """Test main function with no command."""
        with patch('sys.argv', ['myvault.py']):
            with pytest.raises(SystemExit):
                myvault.main()
    
    @patch.dict(os.environ, {}, clear=True)
    @patch('getpass.getpass', side_effect=EOFError)
    def test_main_no_vault_password(self, mock_getpass, capsys):
        """Test main function without VAULT_PASSWORD falls back to prompt; EOFError causes exit."""
        with patch('sys.argv', ['myvault.py', 'validate', '-i', 'test.json']):
            with pytest.raises(SystemExit):
                myvault.main()
        mock_getpass.assert_called_once()
    
    @patch.dict(os.environ, {'VAULT_PASSWORD': 'test_password'})
    @patch('myvault.handle_validate')
    def test_main_validate_command(self, mock_handle):
        """Test main function with validate command."""
        with patch('sys.argv', ['myvault.py', 'validate', '-i', 'test.json']):
            myvault.main()
            mock_handle.assert_called_once()
    
    @patch.dict(os.environ, {'VAULT_PASSWORD': 'test_password'})
    @patch('myvault.handle_read')
    def test_main_read_command(self, mock_handle):
        """Test main function with read command."""
        with patch('sys.argv', ['myvault.py', '-f', 'vault.json', 'read']):
            myvault.main()
            mock_handle.assert_called_once()
    
    @patch.dict(os.environ, {'VAULT_PASSWORD': 'test_password'})
    @patch('myvault.handle_validate')
    def test_main_vault_error_handling(self, mock_handle):
        """Test main function VaultError handling."""
        mock_handle.side_effect = VaultError("Test error")
        
        with patch('sys.argv', ['myvault.py', 'validate', '-i', 'test.json']):
            with pytest.raises(SystemExit):
                myvault.main()
    
    @patch.dict(os.environ, {'VAULT_PASSWORD': 'test_password'})
    @patch('myvault.handle_validate')
    def test_main_keyboard_interrupt(self, mock_handle):
        """Test main function KeyboardInterrupt handling."""
        mock_handle.side_effect = KeyboardInterrupt()
        
        with patch('sys.argv', ['myvault.py', 'validate', '-i', 'test.json']):
            with pytest.raises(SystemExit):
                myvault.main()
    
    @patch.dict(os.environ, {'VAULT_PASSWORD': 'test_password'})
    @patch('myvault.handle_validate')
    def test_main_unexpected_error(self, mock_handle):
        """Test main function unexpected error handling."""
        mock_handle.side_effect = Exception("Unexpected error")
        
        with patch('sys.argv', ['myvault.py', 'validate', '-i', 'test.json']):
            with pytest.raises(SystemExit):
                myvault.main()


class TestEditCommand:
    """Tests for the handle_edit subcommand."""

    SAMPLE_VAULT_DATA = [
        {"property": "website1.com", "username": "user1", "password": "secret1"},
        {"property": "api.service", "username": "api", "password": "token"},
    ]

    def _make_args(self, file="vault.json", editor=None):
        args = MagicMock()
        args.file = file
        args.editor = editor
        return args

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    def test_handle_edit_no_file(self, mock_validate, mock_vault_class):
        """Test that missing -f/--file raises VaultError."""
        args = self._make_args(file=None)
        with pytest.raises(VaultError, match="required for edit command"):
            myvault.handle_edit(args, "password")

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('subprocess.call', return_value=0)
    @patch('tempfile.mkstemp')
    def test_handle_edit_success(self, mock_mkstemp, mock_subproc, mock_validate,
                                  mock_vault_class, tmp_path, capsys):
        """Test successful edit: loads vault, opens editor, validates, saves."""
        tmp_file = tmp_path / "myvault_edit_test.json"
        tmp_file.write_text(json.dumps(self.SAMPLE_VAULT_DATA))
        mock_mkstemp.return_value = (os.open(str(tmp_file), os.O_RDWR), str(tmp_file))

        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = self.SAMPLE_VAULT_DATA
        mock_vault_class.return_value = mock_vault

        args = self._make_args(editor="vi")
        myvault.handle_edit(args, "password")

        mock_subproc.assert_called_once_with(["vi", str(tmp_file)])
        mock_vault.save_vault_file.assert_called_once()
        captured = capsys.readouterr()
        assert "saved successfully" in captured.out

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('subprocess.call', return_value=0)
    @patch('tempfile.mkstemp')
    def test_handle_edit_uses_cli_editor(self, mock_mkstemp, mock_subproc, mock_validate,
                                          mock_vault_class, tmp_path):
        """Test that --editor flag takes priority over $EDITOR."""
        tmp_file = tmp_path / "myvault_edit_test.json"
        tmp_file.write_text(json.dumps(self.SAMPLE_VAULT_DATA))
        mock_mkstemp.return_value = (os.open(str(tmp_file), os.O_RDWR), str(tmp_file))

        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = self.SAMPLE_VAULT_DATA
        mock_vault_class.return_value = mock_vault

        with patch.dict(os.environ, {"EDITOR": "emacs"}):
            args = self._make_args(editor="nano")
            myvault.handle_edit(args, "password")

        called_editor = mock_subproc.call_args[0][0][0]
        assert called_editor == "nano"

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('subprocess.call', return_value=0)
    @patch('tempfile.mkstemp')
    def test_handle_edit_uses_env_editor(self, mock_mkstemp, mock_subproc, mock_validate,
                                          mock_vault_class, tmp_path):
        """Test that $EDITOR is used when --editor is not provided."""
        tmp_file = tmp_path / "myvault_edit_test.json"
        tmp_file.write_text(json.dumps(self.SAMPLE_VAULT_DATA))
        mock_mkstemp.return_value = (os.open(str(tmp_file), os.O_RDWR), str(tmp_file))

        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = self.SAMPLE_VAULT_DATA
        mock_vault_class.return_value = mock_vault

        with patch.dict(os.environ, {"EDITOR": "emacs"}, clear=False):
            args = self._make_args(editor=None)
            myvault.handle_edit(args, "password")

        called_editor = mock_subproc.call_args[0][0][0]
        assert called_editor == "emacs"

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('subprocess.call', return_value=0)
    @patch('tempfile.mkstemp')
    def test_handle_edit_defaults_to_vi(self, mock_mkstemp, mock_subproc, mock_validate,
                                         mock_vault_class, tmp_path):
        """Test that vi is the default editor when neither --editor nor $EDITOR is set."""
        tmp_file = tmp_path / "myvault_edit_test.json"
        tmp_file.write_text(json.dumps(self.SAMPLE_VAULT_DATA))
        mock_mkstemp.return_value = (os.open(str(tmp_file), os.O_RDWR), str(tmp_file))

        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = self.SAMPLE_VAULT_DATA
        mock_vault_class.return_value = mock_vault

        env_without_editor = {k: v for k, v in os.environ.items() if k != "EDITOR"}
        with patch.dict(os.environ, env_without_editor, clear=True):
            args = self._make_args(editor=None)
            myvault.handle_edit(args, "password")

        called_editor = mock_subproc.call_args[0][0][0]
        assert called_editor == "vi"

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('subprocess.call', return_value=1)
    @patch('tempfile.mkstemp')
    def test_handle_edit_editor_nonzero_exit(self, mock_mkstemp, mock_subproc, mock_validate,
                                              mock_vault_class, tmp_path, capsys):
        """Test that a non-zero editor exit code aborts without saving."""
        tmp_file = tmp_path / "myvault_edit_test.json"
        tmp_file.write_text(json.dumps(self.SAMPLE_VAULT_DATA))
        mock_mkstemp.return_value = (os.open(str(tmp_file), os.O_RDWR), str(tmp_file))

        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = self.SAMPLE_VAULT_DATA
        mock_vault_class.return_value = mock_vault

        args = self._make_args(editor="vi")
        myvault.handle_edit(args, "password")

        mock_vault.save_vault_file.assert_not_called()
        captured = capsys.readouterr()
        assert "Changes not saved" in captured.err

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('tempfile.mkstemp')
    def test_handle_edit_editor_nonzero_exit_but_file_modified(
            self, mock_mkstemp, mock_validate, mock_vault_class, tmp_path, capsys):
        """Test that a non-zero exit code is tolerated when the editor modified the file.

        Reproduces the case where a vim plugin (e.g. ALE) exits with code 1 after a
        successful :wq on a file that contains a blank field, causing the edit to be
        discarded even though the user intended to save.
        """
        tmp_file = tmp_path / "myvault_edit_test.json"
        tmp_file.write_text(json.dumps(self.SAMPLE_VAULT_DATA))
        mock_mkstemp.return_value = (os.open(str(tmp_file), os.O_RDWR), str(tmp_file))

        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = self.SAMPLE_VAULT_DATA
        mock_vault_class.return_value = mock_vault

        new_entry = {"property": "newsite.com", "username": "newuser", "password": "newpass"}
        modified_data = self.SAMPLE_VAULT_DATA + [new_entry]

        def editor_writes_and_exits_nonzero(cmd):
            with open(cmd[1], 'w', encoding='utf-8', newline='\n') as f:
                json.dump(modified_data, f, indent=2)
            return 1  # simulates a vim plugin exiting non-zero after a clean write

        args = self._make_args(editor="vi")
        with patch('subprocess.call', side_effect=editor_writes_and_exits_nonzero):
            myvault.handle_edit(args, "password")

        mock_vault.save_vault_file.assert_called_once()
        captured = capsys.readouterr()
        assert "saved successfully" in captured.out

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('builtins.input', return_value='n')
    @patch('tempfile.mkstemp')
    def test_handle_edit_invalid_json_cancel(self, mock_mkstemp, mock_input, mock_validate,
                                              mock_vault_class, tmp_path, capsys):
        """Test that invalid JSON followed by cancel aborts without saving."""
        tmp_file = tmp_path / "myvault_edit_test.json"
        tmp_file.write_text(json.dumps(self.SAMPLE_VAULT_DATA))
        mock_mkstemp.return_value = (os.open(str(tmp_file), os.O_RDWR), str(tmp_file))

        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = self.SAMPLE_VAULT_DATA
        mock_vault_class.return_value = mock_vault

        # Simulate editor writing invalid JSON to the temp file
        def corrupt_file(cmd):
            with open(cmd[1], 'w') as f:
                f.write("this is not valid json {{{")
            return 0

        args = self._make_args(editor="vi")
        with patch('subprocess.call', side_effect=corrupt_file):
            myvault.handle_edit(args, "password")

        mock_vault.save_vault_file.assert_not_called()
        captured = capsys.readouterr()
        assert "cancelled" in captured.out.lower()

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('tempfile.mkstemp')
    def test_handle_edit_invalid_json_retry_then_success(self, mock_mkstemp, mock_validate,
                                                          mock_vault_class, tmp_path, capsys):
        """Test that invalid JSON + 'y' re-opens the editor, and a valid second save succeeds."""
        tmp_file = tmp_path / "myvault_edit_test.json"
        tmp_file.write_text(json.dumps(self.SAMPLE_VAULT_DATA))
        mock_mkstemp.return_value = (os.open(str(tmp_file), os.O_RDWR), str(tmp_file))

        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = self.SAMPLE_VAULT_DATA
        mock_vault_class.return_value = mock_vault

        call_count = [0]

        def editor_side_effect(cmd):
            call_count[0] += 1
            if call_count[0] == 1:
                # First call: write invalid JSON
                with open(cmd[1], 'w') as f:
                    f.write("not valid json {{{")
            else:
                # Second call: write valid JSON
                with open(cmd[1], 'w') as f:
                    json.dump(self.SAMPLE_VAULT_DATA, f)
            return 0

        args = self._make_args(editor="vi")
        with patch('subprocess.call', side_effect=editor_side_effect), \
             patch('builtins.input', return_value='y'):
            myvault.handle_edit(args, "password")

        assert call_count[0] == 2, "Editor should be opened twice (once invalid, once valid)"
        mock_vault.save_vault_file.assert_called_once()
        captured = capsys.readouterr()
        assert "saved successfully" in captured.out

    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('subprocess.call', return_value=0)
    @patch('tempfile.mkstemp')
    def test_handle_edit_temp_file_cleaned_up(self, mock_mkstemp, mock_subproc, mock_validate,
                                               mock_vault_class, tmp_path):
        """Test that the temp file is deleted after editing."""
        tmp_file = tmp_path / "myvault_edit_test.json"
        tmp_file.write_text(json.dumps(self.SAMPLE_VAULT_DATA))
        mock_mkstemp.return_value = (os.open(str(tmp_file), os.O_RDWR), str(tmp_file))

        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = self.SAMPLE_VAULT_DATA
        mock_vault_class.return_value = mock_vault

        args = self._make_args(editor="vi")
        myvault.handle_edit(args, "password")

        assert not tmp_file.exists(), "Temporary edit file should be deleted after editing"

    @patch.dict(os.environ, {'VAULT_PASSWORD': 'test_password'})
    @patch('myvault.handle_edit')
    def test_main_routes_edit_command(self, mock_handle_edit):
        """Test that main() routes 'edit' command to handle_edit."""
        with patch('sys.argv', ['myvault.py', '-f', 'vault.json', 'edit']):
            myvault.main()
        mock_handle_edit.assert_called_once()


class TestSecureTmpdir:
    """Unit tests for the _secure_tmpdir() context manager."""

    @patch('platform.system', return_value='Linux')
    @patch('os.path.isdir', return_value=True)
    def test_linux_uses_dev_shm(self, mock_isdir, mock_system):
        """On Linux with /dev/shm available, mkdtemp is called with dir='/dev/shm'."""
        with patch('tempfile.mkdtemp', return_value='/dev/shm/myvault_test123') as mock_mkdtemp, \
             patch('os.path.exists', return_value=True), \
             patch('shutil.rmtree'):
            with myvault._secure_tmpdir() as tmpdir:
                assert tmpdir == '/dev/shm/myvault_test123'
            mock_mkdtemp.assert_called_once_with(dir='/dev/shm', prefix='myvault_')

    @patch('platform.system', return_value='Linux')
    @patch('os.path.isdir', return_value=False)
    def test_linux_without_shm_falls_back_to_disk(self, mock_isdir, mock_system, capsys):
        """On Linux without /dev/shm, falls back to a regular temp dir with a warning."""
        with patch('tempfile.mkdtemp', return_value='/tmp/myvault_fallback') as mock_mkdtemp, \
             patch('os.path.exists', return_value=True), \
             patch('shutil.rmtree'):
            with myvault._secure_tmpdir() as tmpdir:
                assert tmpdir == '/tmp/myvault_fallback'
            mock_mkdtemp.assert_called_once_with(prefix='myvault_')
        captured = capsys.readouterr()
        assert 'disk' in captured.err.lower() or 'warning' in captured.err.lower()

    @patch('platform.system', return_value='Windows')
    def test_unknown_platform_falls_back_to_disk(self, mock_system, capsys):
        """On an unsupported platform, falls back to a regular temp dir with a warning."""
        with patch('tempfile.mkdtemp', return_value='/tmp/myvault_fallback') as mock_mkdtemp, \
             patch('os.path.exists', return_value=True), \
             patch('shutil.rmtree'):
            with myvault._secure_tmpdir() as tmpdir:
                assert tmpdir == '/tmp/myvault_fallback'
            mock_mkdtemp.assert_called_once_with(prefix='myvault_')
        captured = capsys.readouterr()
        assert 'disk' in captured.err.lower() or 'warning' in captured.err.lower()

    @patch('platform.system', return_value='Linux')
    @patch('os.path.isdir', return_value=True)
    def test_cleanup_removes_tmpdir(self, mock_isdir, mock_system, tmp_path):
        """The tmpdir is removed via shutil.rmtree when the context exits normally."""
        # Use a real subdirectory so os.path.exists returns True and rmtree has something to delete
        secure_dir = tmp_path / 'simulated_shm' / 'myvault_test'
        secure_dir.mkdir(parents=True)
        with patch('tempfile.mkdtemp', return_value=str(secure_dir)):
            with myvault._secure_tmpdir() as tmpdir:
                assert tmpdir == str(secure_dir)
                assert secure_dir.exists()
        assert not secure_dir.exists(), 'tmpdir should be removed after context exits'

    @patch('platform.system', return_value='Linux')
    @patch('os.path.isdir', return_value=True)
    def test_cleanup_runs_even_on_exception(self, mock_isdir, mock_system, tmp_path):
        """The tmpdir is cleaned up even if an exception is raised inside the context."""
        secure_dir = tmp_path / 'simulated_shm' / 'myvault_except'
        secure_dir.mkdir(parents=True)
        with patch('tempfile.mkdtemp', return_value=str(secure_dir)):
            with pytest.raises(RuntimeError):
                with myvault._secure_tmpdir():
                    raise RuntimeError('test exception')
        assert not secure_dir.exists(), 'tmpdir should be removed even when an exception occurs'

    @patch('platform.system', return_value='Darwin')
    def test_macos_creates_ram_disk(self, mock_system):
        """On macOS, hdiutil attach and diskutil eraseVolume are called to set up a RAM disk."""
        hdiutil_result = MagicMock()
        hdiutil_result.stdout = '/dev/disk5\n'
        with patch('tempfile.mkdtemp', return_value='/Volumes/myvault_abc/myvault_xyz') as mock_mkdtemp, \
             patch('os.path.exists', return_value=True), \
             patch('shutil.rmtree'), \
             patch('subprocess.run') as mock_run:
            mock_run.side_effect = [hdiutil_result, MagicMock(), MagicMock()]  # attach, erase, detach
            with myvault._secure_tmpdir() as tmpdir:
                assert tmpdir == '/Volumes/myvault_abc/myvault_xyz'

            attach_args = mock_run.call_args_list[0][0][0]
            assert attach_args[0] == 'hdiutil'
            assert 'attach' in attach_args
            assert 'ram://16384' in attach_args

            erase_args = mock_run.call_args_list[1][0][0]
            assert erase_args[0] == 'diskutil'
            assert 'APFS' in erase_args
            assert '/dev/disk5' in erase_args

            mkdtemp_dir = mock_mkdtemp.call_args[1]['dir']
            assert mkdtemp_dir.startswith('/Volumes/')

    @patch('platform.system', return_value='Darwin')
    def test_macos_detaches_ram_disk_on_exit(self, mock_system):
        """The RAM disk is detached via hdiutil detach when the context exits."""
        hdiutil_result = MagicMock()
        hdiutil_result.stdout = '/dev/disk5\n'
        with patch('tempfile.mkdtemp', return_value='/Volumes/myvault_abc/myvault_xyz'), \
             patch('os.path.exists', return_value=True), \
             patch('shutil.rmtree'), \
             patch('subprocess.run') as mock_run:
            mock_run.side_effect = [hdiutil_result, MagicMock(), MagicMock()]  # attach, erase, detach
            with myvault._secure_tmpdir():
                pass

            detach_args = mock_run.call_args_list[2][0][0]
            assert detach_args[0] == 'hdiutil'
            assert 'detach' in detach_args
            assert '/dev/disk5' in detach_args

    @patch('platform.system', return_value='Darwin')
    def test_macos_ram_disk_failure_falls_back(self, mock_system, capsys):
        """If hdiutil fails on macOS, falls back to regular tmpdir with a warning."""
        with patch('tempfile.mkdtemp', return_value='/tmp/myvault_fallback') as mock_mkdtemp, \
             patch('os.path.exists', return_value=True), \
             patch('shutil.rmtree'), \
             patch('subprocess.run', side_effect=Exception('hdiutil not found')):
            with myvault._secure_tmpdir() as tmpdir:
                assert tmpdir == '/tmp/myvault_fallback'
            mock_mkdtemp.assert_called_once_with(prefix='myvault_')
        captured = capsys.readouterr()
        assert 'disk' in captured.err.lower() or 'warning' in captured.err.lower()

    @patch('platform.system', return_value='Darwin')
    def test_macos_no_detach_if_attach_failed(self, mock_system):
        """If hdiutil attach fails, hdiutil detach is NOT called (device is None)."""
        with patch('tempfile.mkdtemp', return_value='/tmp/myvault_fallback'), \
             patch('os.path.exists', return_value=True), \
             patch('shutil.rmtree'), \
             patch('subprocess.run') as mock_run:
            mock_run.side_effect = Exception('hdiutil not found')
            with myvault._secure_tmpdir():
                pass

            # Only one subprocess.run call attempted (hdiutil attach, which failed);
            # detach must not be called because device was never set
            detach_calls = [c for c in mock_run.call_args_list
                            if 'detach' in str(c)]
            assert len(detach_calls) == 0


class TestEditCommandMemorySafety:
    """Tests that handle_edit always writes the decrypted temp file inside _secure_tmpdir."""

    SAMPLE_VAULT_DATA = [
        {'property': 'website1.com', 'username': 'user1', 'password': 'secret1'},
    ]

    def _make_args(self, file='vault.json', editor='vi'):
        args = MagicMock()
        args.file = file
        args.editor = editor
        return args

    @patch('myvault._secure_tmpdir')
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('subprocess.call', return_value=0)
    @patch('tempfile.mkstemp')
    def test_mkstemp_dir_is_from_secure_tmpdir(self, mock_mkstemp, mock_subproc,
                                                mock_validate, mock_vault_class,
                                                mock_secure_tmpdir, tmp_path):
        """mkstemp must be called with dir= pointing to the directory from _secure_tmpdir,
        not a default filesystem location. This is the core 'does not write to disk' guarantee."""
        secure_dir = str(tmp_path / 'ram_backed_dir')
        os.makedirs(secure_dir)

        @contextmanager
        def fake_cm():
            yield secure_dir

        mock_secure_tmpdir.side_effect = fake_cm

        tmp_file = tmp_path / 'myvault_edit_test.json'
        tmp_file.write_text(json.dumps(self.SAMPLE_VAULT_DATA))
        mock_mkstemp.return_value = (os.open(str(tmp_file), os.O_RDWR), str(tmp_file))

        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = self.SAMPLE_VAULT_DATA
        mock_vault_class.return_value = mock_vault

        myvault.handle_edit(self._make_args(), 'password')

        mock_mkstemp.assert_called_once()
        actual_dir = mock_mkstemp.call_args.kwargs.get('dir')
        assert actual_dir == secure_dir, (
            f'Expected mkstemp dir={secure_dir!r} (from _secure_tmpdir), '
            f'got dir={actual_dir!r}. The decrypted vault must only be written '
            f'to the memory-backed directory.'
        )

    @patch('myvault._secure_tmpdir')
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('subprocess.call', return_value=0)
    @patch('tempfile.mkstemp')
    def test_secure_tmpdir_entered_before_any_file_write(self, mock_mkstemp, mock_subproc,
                                                          mock_validate, mock_vault_class,
                                                          mock_secure_tmpdir, tmp_path):
        """_secure_tmpdir context must be entered before mkstemp (i.e., before any write)."""
        call_order = []

        @contextmanager
        def fake_cm():
            call_order.append('tmpdir_entered')
            yield str(tmp_path)

        mock_secure_tmpdir.side_effect = fake_cm

        tmp_file = tmp_path / 'myvault_edit_test.json'
        tmp_file.write_text(json.dumps(self.SAMPLE_VAULT_DATA))

        def tracking_mkstemp(**kwargs):
            call_order.append('mkstemp_called')
            return (os.open(str(tmp_file), os.O_RDWR), str(tmp_file))

        mock_mkstemp.side_effect = tracking_mkstemp

        mock_vault = MagicMock()
        mock_vault.load_vault_file.return_value = self.SAMPLE_VAULT_DATA
        mock_vault_class.return_value = mock_vault

        myvault.handle_edit(self._make_args(), 'password')

        assert 'tmpdir_entered' in call_order
        assert 'mkstemp_called' in call_order
        assert call_order.index('tmpdir_entered') < call_order.index('mkstemp_called'), (
            '_secure_tmpdir must be entered before mkstemp (before any plaintext is written)'
        )

if __name__ == '__main__':
    pytest.main([__file__, '-v'])
