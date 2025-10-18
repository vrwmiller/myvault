"""
Unit tests for getvault.py core functions.

This test suite covers:
- load_vault function (with mocked Ansible vault operations)
- search_records function (with various search patterns)
- CSV parsing logic
- Error handling scenarios
"""

import pytest
import os
import sys
import tempfile
from unittest.mock import Mock, patch, mock_open
from io import StringIO

# Add the parent directory to the path so we can import getvault
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '..'))

# Import the functions we want to test
from getvault import load_vault, search_records


class TestLoadVault:
    """Test cases for the load_vault function."""
    
    def test_load_vault_success(self, mock_vault_components, sample_csv_data):
        """Test successful vault loading and CSV parsing."""
        mock_secret, mock_vault = mock_vault_components
        
        with patch('getvault.VaultSecret', return_value=mock_secret), \
             patch('getvault.VaultLib', return_value=mock_vault), \
             patch('builtins.open', mock_open(read_data=b"encrypted_data")):
            
            mock_vault.decrypt.return_value = sample_csv_data
            
            result = load_vault("test_file.vault", "test_password")
            
            # Verify the result
            expected = [
                ["field1", "field2", "field3"],
                ["test", "value", "description"],
                ["db", "localhost", "database"]
            ]
            assert result == expected
            
            # Verify mocks were called correctly
            mock_vault.decrypt.assert_called_once()

    def test_load_vault_filters_invalid_records(self):
        """Test that records without exactly 3 fields are filtered out."""
        mock_secret = Mock()
        mock_vault = Mock()
        mock_decrypted_data = b"field1~field2~field3\ninvalid~record\ntoo~many~fields~here\nvalid~record~here"
        
        with patch('getvault.VaultSecret', return_value=mock_secret), \
             patch('getvault.VaultLib', return_value=mock_vault), \
             patch('builtins.open', mock_open(read_data=b"encrypted_data")):
            
            mock_vault.decrypt.return_value = mock_decrypted_data
            
            result = load_vault("test_file.vault", "test_password")
            
            # Should only include records with exactly 3 fields
            expected = [
                ["field1", "field2", "field3"],
                ["valid", "record", "here"]
            ]
            assert result == expected

    def test_load_vault_strips_whitespace(self):
        """Test that whitespace is properly stripped from fields."""
        mock_secret = Mock()
        mock_vault = Mock()
        mock_decrypted_data = b"  field1  ~  field2  ~  field3  \n  test  ~  value  ~  description  "
        
        with patch('getvault.VaultSecret', return_value=mock_secret), \
             patch('getvault.VaultLib', return_value=mock_vault), \
             patch('builtins.open', mock_open(read_data=b"encrypted_data")):
            
            mock_vault.decrypt.return_value = mock_decrypted_data
            
            result = load_vault("test_file.vault", "test_password")
            
            # Whitespace should be stripped
            expected = [
                ["field1", "field2", "field3"],
                ["test", "value", "description"]
            ]
            assert result == expected

    def test_load_vault_handles_empty_file(self):
        """Test handling of empty decrypted content."""
        mock_secret = Mock()
        mock_vault = Mock()
        mock_decrypted_data = b""
        
        with patch('getvault.VaultSecret', return_value=mock_secret), \
             patch('getvault.VaultLib', return_value=mock_vault), \
             patch('builtins.open', mock_open(read_data=b"encrypted_data")):
            
            mock_vault.decrypt.return_value = mock_decrypted_data
            
            result = load_vault("test_file.vault", "test_password")
            
            assert result == []

    def test_load_vault_file_not_found(self):
        """Test handling of missing vault file."""
        with pytest.raises(FileNotFoundError):
            load_vault("nonexistent_file.vault", "test_password")

    def test_load_vault_decrypt_error(self):
        """Test handling of decryption errors."""
        mock_secret = Mock()
        mock_vault = Mock()
        mock_vault.decrypt.side_effect = Exception("Decryption failed")
        
        with patch('getvault.VaultSecret', return_value=mock_secret), \
             patch('getvault.VaultLib', return_value=mock_vault), \
             patch('builtins.open', mock_open(read_data=b"encrypted_data")):
            
            with pytest.raises(Exception, match="Decryption failed"):
                load_vault("test_file.vault", "wrong_password")


class TestSearchRecords:
    """Test cases for the search_records function."""
    
    def test_search_records_single_pattern_case_insensitive(self, sample_records, capsys):
        """Test searching with a single pattern (case insensitive)."""
        search_records(sample_records, "database", case_insensitive=True)
        
        captured = capsys.readouterr()
        lines = captured.out.strip().split('\n')
        
        # Should match both "database" and "Database"
        assert len(lines) == 2
        assert "database ~ localhost ~ Main database server" in lines
        assert "Database ~ remote.db ~ Backup database" in lines

    def test_search_records_single_pattern_case_sensitive(self, sample_records, capsys):
        """Test searching with a single pattern (case sensitive)."""
        search_records(sample_records, "database", case_insensitive=False)
        
        captured = capsys.readouterr()
        lines = captured.out.strip().split('\n')
        
        # Should only match "database" (lowercase)
        assert len(lines) == 1
        assert "database ~ localhost ~ Main database server" in lines

    def test_search_records_multiple_patterns(self, sample_records, capsys):
        """Test searching with multiple patterns separated by pipe."""
        search_records(sample_records, "api|token", case_insensitive=True)
        
        captured = capsys.readouterr()
        lines = captured.out.strip().split('\n')
        
        # Should match records containing "api" or "token"
        assert len(lines) == 3
        assert "api_key ~ abc123 ~ Production API key" in lines
        assert "admin_token ~ xyz789 ~ Admin access token" in lines
        assert "web_api ~ def456 ~ Web service API" in lines

    def test_search_records_no_matches(self, sample_records, capsys):
        """Test searching with pattern that has no matches."""
        search_records(sample_records, "nonexistent", case_insensitive=True)
        
        captured = capsys.readouterr()
        assert captured.out.strip() == ""

    def test_search_records_empty_pattern(self, sample_records, capsys):
        """Test searching with empty pattern."""
        search_records(sample_records, "", case_insensitive=True)
        
        captured = capsys.readouterr()
        assert captured.out.strip() == ""

    def test_search_records_whitespace_patterns(self, sample_records, capsys):
        """Test searching with patterns containing whitespace."""
        search_records(sample_records, " api | token ", case_insensitive=True)
        
        captured = capsys.readouterr()
        lines = captured.out.strip().split('\n')
        
        # Should still work with whitespace around patterns
        assert len(lines) == 3
        assert "api_key ~ abc123 ~ Production API key" in lines
        assert "admin_token ~ xyz789 ~ Admin access token" in lines
        assert "web_api ~ def456 ~ Web service API" in lines

    def test_search_records_empty_records_list(self, capsys):
        """Test searching in empty records list."""
        search_records([], "database", case_insensitive=True)
        
        captured = capsys.readouterr()
        assert captured.out.strip() == ""

    def test_search_records_partial_matches(self, sample_records, capsys):
        """Test that partial matches work correctly."""
        search_records(sample_records, "data", case_insensitive=True)
        
        captured = capsys.readouterr()
        lines = captured.out.strip().split('\n')
        
        # Should match both records containing "data" (from "database")
        assert len(lines) == 2
        assert "database ~ localhost ~ Main database server" in lines
        assert "Database ~ remote.db ~ Backup database" in lines

    def test_search_records_pipe_in_field_content(self, capsys):
        """Test handling of pipe characters in field content."""
        records_with_pipes = [
            ["config|setting", "value1", "Configuration with pipe"],
            ["normal_field", "value2", "Normal field"]
        ]
        
        search_records(records_with_pipes, "config", case_insensitive=True)
        
        captured = capsys.readouterr()
        lines = captured.out.strip().split('\n')
        
        assert len(lines) == 1
        assert "config|setting ~ value1 ~ Configuration with pipe" in lines


class TestIntegration:
    """Integration tests combining multiple functions."""
    
    def test_load_and_search_workflow(self, capsys):
        """Test the complete workflow of loading and searching."""
        # Mock the vault loading
        mock_secret = Mock()
        mock_vault = Mock()
        mock_decrypted_data = b"database~localhost~Main DB\napi_key~abc123~Production API\nweb_token~xyz789~Web access"
        
        with patch('getvault.VaultSecret', return_value=mock_secret), \
             patch('getvault.VaultLib', return_value=mock_vault), \
             patch('builtins.open', mock_open(read_data=b"encrypted_data")):
            
            mock_vault.decrypt.return_value = mock_decrypted_data
            
            # Load the vault
            records = load_vault("test_file.vault", "test_password")
            
            # Search the records
            search_records(records, "api|database", case_insensitive=True)
            
            captured = capsys.readouterr()
            lines = captured.out.strip().split('\n')
            
            assert len(lines) == 2
            assert "database ~ localhost ~ Main DB" in lines
            assert "api_key ~ abc123 ~ Production API" in lines


if __name__ == "__main__":
    pytest.main([__file__, "-v"])