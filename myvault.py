#!/usr/bin/env python3
"""
MyVault - JSON-based Ansible Vault Secret Manager

A utility script for managing JSON-formatted secrets encrypted with Ansible Vault.
Supports CRUD operations on extensible property-based secret entries.

JSON Structure:
[
    {
        "property": "website1.com",
        "username": "user@domain.com", 
        "password": "secret123",
        "apitoken": "optional_token",
        // ... other arbitrary secrets
    }
]

Requirements:
- VAULT_PASSWORD environment variable must be set
- Input JSON files must have secure permissions (600)
- Secrets are never exposed in logs or command line
"""

import os
import sys
import json
import logging
import argparse
import stat
import fnmatch
from pathlib import Path
from typing import Dict, List, Any, Optional, Union
from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultSecret, VaultLib


from ansible.parsing.vault import VaultSecret, VaultLib


def setup_logging(debug_mode=False):
    """Configure logging to file by default, console only in debug mode."""
    # Clear any existing handlers
    root_logger = logging.getLogger()
    for handler in root_logger.handlers[:]:
        root_logger.removeHandler(handler)
    
    # Configure handlers
    handlers = []
    
    # Always log to file
    file_handler = logging.FileHandler('myvault.log', mode='a')
    file_handler.setFormatter(logging.Formatter(
        '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
    ))
    handlers.append(file_handler)
    
    # Add console logging only in debug mode
    if debug_mode:
        console_handler = logging.StreamHandler()
        console_handler.setFormatter(logging.Formatter(
            '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
        ))
        handlers.append(console_handler)
    
    # Configure logging
    logging.basicConfig(
        level=logging.INFO,
        handlers=handlers,
        force=True  # Override any existing configuration
    )


logger = logging.getLogger(__name__)


class VaultError(Exception):
    """Custom exception for vault operations."""
    pass


def match_property_expression(property_value: str, expression: str) -> bool:
    """
    Match a property value against an expression that supports:
    - Pipe-separated alternatives: "web1|web2|api" 
    - Glob patterns: "web*.com", "api?", "*database*"
    - Exact matches: "website1.com"
    
    Args:
        property_value: The property value to test
        expression: The expression to match against
        
    Returns:
        True if the property matches the expression
    """
    if not expression or not property_value:
        return False
    
    # Split by pipe to handle multiple alternatives
    alternatives = [alt.strip() for alt in expression.split('|') if alt.strip()]
    
    for alternative in alternatives:
        # Use fnmatch for glob pattern support
        if fnmatch.fnmatch(property_value.lower(), alternative.lower()):
            return True
    
    return False


class JSONValidator:
    """Validates JSON structure and file permissions."""
    
    REQUIRED_FIELDS = ["property"]
    COMMON_FIELDS = ["username", "password", "apitoken", "notes"]
    
    @staticmethod
    def validate_file_permissions(file_path: str) -> None:
        """Ensure file has secure permissions (600 - owner read/write only)."""
        if not os.path.exists(file_path):
            return
            
        file_stat = os.stat(file_path)
        permissions = stat.filemode(file_stat.st_mode)
        
        # Check that group and other have no permissions
        if file_stat.st_mode & (stat.S_IRGRP | stat.S_IWGRP | stat.S_IXGRP |
                              stat.S_IROTH | stat.S_IWOTH | stat.S_IXOTH):
            raise VaultError(f"Insecure file permissions on {file_path}. "
                           f"Current: {permissions}. Required: -rw------- (600)")
        
        logger.info(f"File permissions validated for {file_path}")
    
    @staticmethod
    def validate_json_structure(data: Union[List, Dict]) -> List[Dict]:
        """Validate JSON structure and return normalized list."""
        if isinstance(data, dict):
            data = [data]
        
        if not isinstance(data, list):
            raise VaultError("JSON must be a list of objects or a single object")
        
        validated_entries = []
        for i, entry in enumerate(data):
            if not isinstance(entry, dict):
                raise VaultError(f"Entry {i} must be an object")
            
            # Check required fields
            for field in JSONValidator.REQUIRED_FIELDS:
                if field not in entry:
                    raise VaultError(f"Entry {i} missing required field: {field}")
            
            # Validate property field is not empty
            if not entry.get("property", "").strip():
                raise VaultError(f"Entry {i} has empty property field")
            
            validated_entries.append(entry)
        
        logger.info(f"Validated {len(validated_entries)} JSON entries")
        return validated_entries


class VaultManager:
    """Handles Ansible Vault encryption/decryption operations."""
    
    def __init__(self, password: str):
        """Initialize vault manager with password."""
        self.secret = VaultSecret(password.encode())
        self.vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, self.secret)])
        logger.info("Vault manager initialized")
    
    def encrypt_data(self, data: List[Dict]) -> bytes:
        """Encrypt JSON data to vault format."""
        try:
            json_str = json.dumps(data, indent=2, ensure_ascii=False)
            encrypted_data = self.vault.encrypt(json_str.encode('utf-8'))
            logger.info(f"Encrypted {len(data)} entries")
            return encrypted_data
        except Exception as e:
            logger.error(f"Encryption failed: {type(e).__name__}")
            raise VaultError(f"Failed to encrypt data: {e}")
    
    def decrypt_data(self, encrypted_data: bytes) -> List[Dict]:
        """Decrypt vault data to JSON structure."""
        try:
            decrypted_bytes = self.vault.decrypt(encrypted_data)
            json_str = decrypted_bytes.decode('utf-8')
            data = json.loads(json_str)
            
            # Normalize to list format
            if isinstance(data, dict):
                data = [data]
            
            logger.info(f"Decrypted {len(data)} entries")
            return data
        except json.JSONDecodeError as e:
            logger.error(f"JSON decode failed: {e}")
            raise VaultError(f"Invalid JSON in vault file: {e}")
        except Exception as e:
            logger.error(f"Decryption failed: {type(e).__name__}")
            raise VaultError(f"Failed to decrypt data: {e}")
    
    def load_vault_file(self, file_path: str) -> List[Dict]:
        """Load and decrypt vault file."""
        try:
            with open(file_path, 'rb') as f:
                encrypted_data = f.read()
            
            if not encrypted_data.strip():
                logger.info(f"Empty vault file: {file_path}")
                return []
            
            return self.decrypt_data(encrypted_data)
        except FileNotFoundError:
            logger.info(f"Vault file not found: {file_path}")
            return []
        except Exception as e:
            logger.error(f"Failed to load vault file {file_path}: {type(e).__name__}")
            raise VaultError(f"Failed to load vault file: {e}")
    
    def save_vault_file(self, file_path: str, data: List[Dict]) -> None:
        """Encrypt and save data to vault file."""
        try:
            encrypted_data = self.encrypt_data(data)
            
            # Ensure secure permissions before writing
            Path(file_path).touch(mode=0o600)
            
            with open(file_path, 'wb') as f:
                f.write(encrypted_data)
            
            # Double-check permissions after write
            JSONValidator.validate_file_permissions(file_path)
            logger.info(f"Saved {len(data)} entries to {file_path}")
            
        except Exception as e:
            logger.error(f"Failed to save vault file {file_path}: {type(e).__name__}")
            raise VaultError(f"Failed to save vault file: {e}")


def main():
    """Main entry point."""
    parser = argparse.ArgumentParser(
        description="MyVault - JSON-based Ansible Vault Secret Manager",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  myvault.py validate -i secrets.json
  myvault.py create -f vault.json -i new_secrets.json
  myvault.py read -f vault.json --property website1.com
  myvault.py read -f vault.json --property "web*|*api*"
  myvault.py read -f vault.json --property "*.com|database.*"
  myvault.py update -f vault.json -i updates.json
  myvault.py delete -f vault.json --property website1.com
  myvault.py delete -f vault.json --property "web*|test.*"
  myvault.py delete -f vault.json --property "*.old" --force
        """
    )
    
    # Global options
    parser.add_argument('-f', '--file', 
                       help='Path to encrypted vault file')
    parser.add_argument('-d', '--debug', action='store_true',
                       help='Enable debug logging to console (logs always written to myvault.log)')
    
    # Subcommands
    subparsers = parser.add_subparsers(dest='command', help='Available commands')
    
    # Validate command
    validate_parser = subparsers.add_parser('validate', 
                                          help='Validate JSON input file')
    validate_parser.add_argument('-i', '--input', required=True,
                               help='JSON file to validate')
    
    # Read command  
    read_parser = subparsers.add_parser('read',
                                      help='Read entries from vault')
    read_parser.add_argument('--property',
                           help='Filter by property expression (supports glob patterns and | for multiple: "web*|*api*|exact.match")')
    read_parser.add_argument('-o', '--output',
                           help='Output to JSON file instead of STDOUT')
    
    # Create command
    create_parser = subparsers.add_parser('create',
                                        help='Create new vault entries')
    create_parser.add_argument('-i', '--input', required=True,
                             help='JSON file with new entries')
    
    # Update command
    update_parser = subparsers.add_parser('update',
                                        help='Update existing vault entries')
    update_parser.add_argument('-i', '--input', required=True,
                             help='JSON file with updated entries')
    
    # Delete command
    delete_parser = subparsers.add_parser('delete',
                                        help='Delete vault entries')
    delete_parser.add_argument('--property', required=True,
                             help='Property expression to delete (supports glob patterns and | for multiple: "web*|*api*|exact.match")')
    delete_parser.add_argument('--force', action='store_true',
                             help='Skip confirmation prompt')
    
    args = parser.parse_args()
    
    if not args.command:
        parser.print_help()
        sys.exit(1)
    
    # Setup logging based on debug mode
    setup_logging(debug_mode=args.debug)
    
    # Set debug level if requested
    if args.debug:
        logging.getLogger().setLevel(logging.DEBUG)
    
    # Get vault password from environment
    vault_password = os.environ.get("VAULT_PASSWORD")
    if not vault_password:
        logger.error("VAULT_PASSWORD environment variable not set")
        print("Error: VAULT_PASSWORD environment variable not set", file=sys.stderr)
        sys.exit(1)
    
    try:
        # Route to appropriate command handler
        if args.command == 'validate':
            handle_validate(args)
        elif args.command == 'read':
            handle_read(args, vault_password)
        elif args.command == 'create':
            handle_create(args, vault_password)
        elif args.command == 'update':
            handle_update(args, vault_password)
        elif args.command == 'delete':
            handle_delete(args, vault_password)
        
    except VaultError as e:
        logger.error(f"Vault operation failed: {e}")
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        logger.info("Operation cancelled by user")
        print("Operation cancelled by user", file=sys.stderr)
        sys.exit(1)
    except Exception as e:
        logger.error(f"Unexpected error: {e}")
        print(f"Unexpected error: {e}", file=sys.stderr)
        sys.exit(1)


def handle_validate(args) -> None:
    """Handle validate subcommand."""
    logger.info(f"Validating JSON file: {args.input}")
    
    # Check if file exists
    if not os.path.exists(args.input):
        raise VaultError(f"Input file not found: {args.input}")
    
    # Validate file permissions
    JSONValidator.validate_file_permissions(args.input)
    
    # Load and validate JSON structure
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            raw_data = json.load(f)
        
        # Validate structure
        validated_entries = JSONValidator.validate_json_structure(raw_data)
        
        # Report validation results
        logger.info(f"✓ JSON file structure is valid")
        logger.info(f"✓ File permissions are secure")
        logger.info(f"✓ Found {len(validated_entries)} valid entries")
        
        # Show summary of properties
        properties = [entry.get("property", "UNKNOWN") for entry in validated_entries]
        logger.info(f"Properties found: {', '.join(properties)}")
        
        # Check for duplicate properties
        if len(properties) != len(set(properties)):
            duplicates = [prop for prop in set(properties) if properties.count(prop) > 1]
            logger.warning(f"Duplicate properties detected: {', '.join(duplicates)}")
        
        # Show field usage summary
        all_fields = set()
        for entry in validated_entries:
            all_fields.update(entry.keys())
        
        logger.info(f"All fields used: {', '.join(sorted(all_fields))}")
        
        print("JSON validation completed successfully!")
        
    except json.JSONDecodeError as e:
        raise VaultError(f"Invalid JSON syntax in {args.input}: {e}")
    except Exception as e:
        raise VaultError(f"Validation failed: {e}")


def handle_read(args, vault_password: str) -> None:
    """Handle read subcommand."""
    if not args.file:
        raise VaultError("Vault file (-f/--file) is required for read command")
    
    logger.info(f"Reading from vault file: {args.file}")
    
    # Validate vault file permissions
    JSONValidator.validate_file_permissions(args.file)
    
    # Load vault data
    vault_manager = VaultManager(vault_password)
    vault_data = vault_manager.load_vault_file(args.file)
    
    if not vault_data:
        logger.info("No entries found in vault file")
        print("No entries found")
        return
    
    # Filter by property expression if specified
    filtered_data = vault_data
    if args.property:
        filtered_data = [entry for entry in vault_data 
                        if match_property_expression(
                            entry.get("property", ""), 
                            args.property
                        )]
        
        if not filtered_data:
            logger.info(f"No entries found matching property expression: {args.property}")
            print(f"No entries found matching property expression: {args.property}")
            return
        
        logger.info(f"Found {len(filtered_data)} entries matching property expression: {args.property}")
    else:
        logger.info(f"Showing all {len(filtered_data)} entries")
    
    # Output results
    if args.output:
        # Write to output file with secure permissions
        Path(args.output).touch(mode=0o600)
        with open(args.output, 'w', encoding='utf-8') as f:
            json.dump(filtered_data, f, indent=2, ensure_ascii=False)
        
        JSONValidator.validate_file_permissions(args.output)
        logger.info(f"Results written to: {args.output}")
        print(f"Results written to: {args.output}")
    else:
        # Output to STDOUT - show all values unmasked in compact single-line format
        for entry in filtered_data:
            # Create a compact single-line representation with logical field ordering
            parts = []
            
            # Always show property value first
            if 'property' in entry:
                parts.append(str(entry['property']))
            
            # Then username if present
            if 'username' in entry:
                parts.append(str(entry['username']))
            
            # Then secrets/passwords in common order
            secret_fields = ['password', 'secret', 'apitoken', 'token', 'key', 'apikey']
            for field in secret_fields:
                if field in entry:
                    value = entry[field]
                    if value is None:
                        value = "null"
                    else:
                        value = str(value)
                    parts.append(value)
            
            # Finally, add remaining fields in alphabetical order
            processed_fields = {'property', 'username'} | set(secret_fields)
            remaining_fields = [k for k in sorted(entry.keys()) if k not in processed_fields]
            for key in remaining_fields:
                value = entry[key]
                # Format boolean and None values nicely
                if isinstance(value, bool):
                    value = str(value).lower()
                elif value is None:
                    value = "null"
                else:
                    value = str(value)
                parts.append(value)
            
            print(" | ".join(parts))


def handle_create(args, vault_password: str) -> None:
    """Handle create subcommand."""
    if not args.file:
        raise VaultError("Vault file (-f/--file) is required for create command")
    
    logger.info(f"Creating entries in vault file: {args.file}")
    
    # Validate input file
    if not os.path.exists(args.input):
        raise VaultError(f"Input file not found: {args.input}")
    
    JSONValidator.validate_file_permissions(args.input)
    
    # Load and validate input JSON
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            input_data = json.load(f)
        
        new_entries = JSONValidator.validate_json_structure(input_data)
        logger.info(f"Loaded {len(new_entries)} entries from input file")
        
    except json.JSONDecodeError as e:
        raise VaultError(f"Invalid JSON in input file: {e}")
    
    # Load existing vault data
    vault_manager = VaultManager(vault_password)
    existing_data = vault_manager.load_vault_file(args.file)
    
    # Check for property conflicts
    existing_properties = {entry.get("property", "").lower() for entry in existing_data}
    new_properties = [entry.get("property", "") for entry in new_entries]
    
    conflicts = [prop for prop in new_properties 
                if prop.lower() in existing_properties]
    
    if conflicts:
        logger.warning(f"Property conflicts detected: {', '.join(conflicts)}")
        response = input(f"Properties already exist: {', '.join(conflicts)}. "
                        f"Continue anyway? (y/N): ")
        if response.lower() not in ['y', 'yes']:
            logger.info("Create operation cancelled by user")
            return
    
    # Merge data
    merged_data = existing_data + new_entries
    logger.info(f"Merging {len(existing_data)} existing + {len(new_entries)} new = "
               f"{len(merged_data)} total entries")
    
    # Save to vault
    vault_manager.save_vault_file(args.file, merged_data)
    
    print(f"Successfully created {len(new_entries)} entries in vault file")
    print(f"Total entries in vault: {len(merged_data)}")


def handle_update(args, vault_password: str) -> None:
    """Handle update subcommand."""
    if not args.file:
        raise VaultError("Vault file (-f/--file) is required for update command")
    
    logger.info(f"Updating entries in vault file: {args.file}")
    
    # Validate input file
    if not os.path.exists(args.input):
        raise VaultError(f"Input file not found: {args.input}")
    
    JSONValidator.validate_file_permissions(args.input)
    
    # Load and validate input JSON
    try:
        with open(args.input, 'r', encoding='utf-8') as f:
            input_data = json.load(f)
        
        update_entries = JSONValidator.validate_json_structure(input_data)
        logger.info(f"Loaded {len(update_entries)} update entries from input file")
        
    except json.JSONDecodeError as e:
        raise VaultError(f"Invalid JSON in input file: {e}")
    
    # Load existing vault data
    vault_manager = VaultManager(vault_password)
    existing_data = vault_manager.load_vault_file(args.file)
    
    if not existing_data:
        raise VaultError("No existing entries found in vault file")
    
    # Build property index for existing data
    property_index = {}
    for i, entry in enumerate(existing_data):
        prop = entry.get("property", "").lower()
        if prop in property_index:
            logger.warning(f"Duplicate property in vault: {prop}")
        property_index[prop] = i
    
    # Process updates
    updated_count = 0
    not_found = []
    
    for update_entry in update_entries:
        update_prop = update_entry.get("property", "").lower()
        
        if update_prop in property_index:
            # Update existing entry
            index = property_index[update_prop]
            original_entry = existing_data[index].copy()
            
            # Merge update fields into existing entry
            for key, value in update_entry.items():
                existing_data[index][key] = value
            
            updated_count += 1
            logger.info(f"Updated property: {update_entry.get('property')}")
            
        else:
            not_found.append(update_entry.get("property", "UNKNOWN"))
    
    # Report results
    if not_found:
        logger.warning(f"Properties not found for update: {', '.join(not_found)}")
        response = input(f"Some properties were not found. Continue with updates? (y/N): ")
        if response.lower() not in ['y', 'yes']:
            logger.info("Update operation cancelled by user")
            return
    
    if updated_count == 0:
        logger.info("No entries were updated")
        print("No entries were updated")
        return
    
    # Save updated vault
    vault_manager.save_vault_file(args.file, existing_data)
    
    print(f"Successfully updated {updated_count} entries in vault file")
    if not_found:
        print(f"Properties not found: {', '.join(not_found)}")


def handle_delete(args, vault_password: str) -> None:
    """Handle delete subcommand with property expression support."""
    if not args.file:
        raise VaultError("Vault file (-f/--file) is required for delete command")
    
    logger.info(f"Deleting entries from vault file: {args.file}")
    
    # Load existing vault data
    vault_manager = VaultManager(vault_password)
    existing_data = vault_manager.load_vault_file(args.file)
    
    if not existing_data:
        logger.info("No entries found in vault file")
        print("No entries found in vault file")
        return
    
    # Find entries to delete using property expression
    entries_to_delete = []
    for i, entry in enumerate(existing_data):
        if match_property_expression(entry.get("property", ""), args.property):
            entries_to_delete.append((i, entry.copy()))
    
    if not entries_to_delete:
        logger.info(f"No entries found matching property expression: {args.property}")
        print(f"No entries found matching property expression: {args.property}")
        return
    
    # Show what will be deleted and get individual confirmations
    if not args.force:
        confirmed_deletions = []
        
        print(f"Found {len(entries_to_delete)} entries matching expression '{args.property}':")
        print("=" * 60)
        
        for i, (index, entry) in enumerate(entries_to_delete, 1):
            # Display entry (mask sensitive fields)
            display_entry = {}
            for key, value in entry.items():
                if key.lower() in ['password', 'secret', 'token', 'key', 'apitoken']:
                    display_entry[key] = '***MASKED***'
                else:
                    display_entry[key] = value
            
            print(f"\nEntry {i} of {len(entries_to_delete)}:")
            print(json.dumps(display_entry, indent=2, ensure_ascii=False))
            print("-" * 40)
            
            # Ask for confirmation for this specific entry
            while True:
                response = input(f"Delete this entry? (y/n/q to quit): ").lower().strip()
                if response in ['y', 'yes']:
                    confirmed_deletions.append((index, entry))
                    print("✓ Marked for deletion")
                    break
                elif response in ['n', 'no']:
                    print("✗ Skipped")
                    break
                elif response in ['q', 'quit']:
                    print("Delete operation cancelled")
                    logger.info("Delete operation cancelled by user")
                    return
                else:
                    print("Please enter 'y' (yes), 'n' (no), or 'q' (quit)")
        
        print("=" * 60)
        
        if not confirmed_deletions:
            print("No entries selected for deletion")
            logger.info("No entries selected for deletion")
            return
        
        # Final confirmation summary
        print(f"\nSummary: {len(confirmed_deletions)} of {len(entries_to_delete)} entries marked for deletion")
        final_response = input("Proceed with deletion? (y/N): ")
        if final_response.lower() not in ['y', 'yes']:
            logger.info("Delete operation cancelled by user at final confirmation")
            print("Delete operation cancelled")
            return
        
        entries_to_delete = confirmed_deletions
    else:
        # Force mode: show what will be deleted but don't ask for confirmation
        print(f"Force mode: Deleting {len(entries_to_delete)} entries matching expression '{args.property}':")
        print("=" * 60)
        
        for i, (index, entry) in enumerate(entries_to_delete, 1):
            display_entry = {}
            for key, value in entry.items():
                if key.lower() in ['password', 'secret', 'token', 'key', 'apitoken']:
                    display_entry[key] = '***MASKED***'
                else:
                    display_entry[key] = value
            
            print(f"\nEntry {i}:")
            print(json.dumps(display_entry, indent=2, ensure_ascii=False))
        
        print("=" * 60)
    
    # Remove entries (delete in reverse order to maintain indices)
    entries_to_delete.sort(key=lambda x: x[0], reverse=True)
    
    deleted_properties = []
    for index, entry in entries_to_delete:
        deleted_properties.append(entry.get("property", "UNKNOWN"))
        existing_data.pop(index)
    
    logger.info(f"Deleted {len(entries_to_delete)} entries: {', '.join(deleted_properties)}")
    
    # Save updated vault
    if existing_data:
        vault_manager.save_vault_file(args.file, existing_data)
        print(f"Successfully deleted {len(entries_to_delete)} entries. {len(existing_data)} entries remaining.")
    else:
        # Delete vault file if no entries remain
        os.remove(args.file)
        logger.info(f"Removed empty vault file: {args.file}")
        print("Deleted all entries. Vault file removed.")
    
    # Log each deleted property
    for prop in deleted_properties:
        logger.info(f"Deleted property: {prop}")
    
    logger.info(f"Delete operation completed for expression: {args.property}")


if __name__ == "__main__":
    main()