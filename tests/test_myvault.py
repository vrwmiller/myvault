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
from pathlib import Path
from unittest.mock import patch, MagicMock, mock_open
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
        assert "***MASKED***" in captured.out
    
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
        assert "Found 2 entries matching expression '*.old'" in captured.out
        assert "test1.old" in captured.out
        assert "test2.old" in captured.out
        # Should not prompt for confirmation in force mode
        assert "Delete all" not in captured.out
        mock_vault.save_vault_file.assert_called_once()
    
    @patch('myvault.VaultManager')
    @patch('myvault.JSONValidator.validate_file_permissions')
    @patch('builtins.input', return_value='n')
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
        assert "Delete operation cancelled" in captured.out
        # Should not save if cancelled
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
    def test_main_no_vault_password(self, capsys):
        """Test main function without VAULT_PASSWORD."""
        with patch('sys.argv', ['myvault.py', 'validate', '-i', 'test.json']):
            with pytest.raises(SystemExit):
                myvault.main()
    
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


if __name__ == "__main__":
    pytest.main([__file__, "-v"])