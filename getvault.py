#!/usr/bin/env python3
"""
Ansible Vault CSV Reader

A utility script for decrypting and searching through Ansible Vault encrypted CSV files.
The CSV format expected is: field1~field2~field3 (tilde-separated values).

Requirements:
- VAULT_PASSWORD environment variable must be set
- Ansible library must be installed (see requirements.txt)

Usage:
    python getvault.py -f vault_file.csv                    # Display all records
    python getvault.py -f vault_file.csv -s "pattern"       # Search for pattern in field1
    python getvault.py -f vault_file.csv -s "pat1|pat2"     # Search for multiple patterns
"""

import os
import sys
import argparse
from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultSecret, VaultLib

def load_vault(file_path, password):
    """
    Load and decrypt an Ansible Vault encrypted CSV file.
    
    Args:
        file_path (str): Path to the encrypted vault file
        password (str): Vault password for decryption
        
    Returns:
        list: List of records, where each record is a list of 3 fields
        
    Raises:
        Exception: If the file cannot be read or decrypted
    """
    # Create vault secret from password
    secret = VaultSecret(password.encode())
    
    # Initialize vault library with the secret
    vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, secret)])
    
    # Read encrypted file content
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    
    # Decrypt the data
    decrypted_data = vault.decrypt(encrypted_data)
    
    # Parse CSV data (tilde-separated format)
    lines = decrypted_data.decode('utf-8').splitlines()
    records = []
    for line in lines:
        # Split on tilde and strip whitespace from each field
        fields = [field.strip() for field in line.split('~')]
        # Only include records with exactly 3 fields
        if len(fields) == 3:
            records.append(fields)
    return records

def search_records(records, search_patterns, case_insensitive=True):
    """
    Search through records and print matching ones.
    
    Searches the first field of each record for any of the given patterns.
    When a match is found, prints all three fields of that record.
    
    Args:
        records (list): List of records to search through
        search_patterns (str): Pipe-separated string of search patterns (e.g., 'pattern1|pattern2')
        case_insensitive (bool): Whether to perform case-insensitive matching
        
    Note:
        - Only searches in field1 (first field) of each record
        - Uses substring matching (not exact matching)
        - Prints records in format: "field1 ~ field2 ~ field3"
    """
    # Split the patterns string on pipe character and clean up whitespace
    patterns = [p.strip() for p in search_patterns.split('|') if p.strip()]
    
    # Search through each record
    for fields in records:
        field1 = fields[0]
        
        # Prepare field for comparison based on case sensitivity
        check_field = field1.lower() if case_insensitive else field1
        
        # Check each pattern against the first field
        for pattern in patterns:
            # Prepare pattern for comparison based on case sensitivity
            pat = pattern.lower() if case_insensitive else pattern
            
            # If pattern found in field1, print the record and move to next record
            if pat in check_field:
                print(" ~ ".join(fields))
                break  # Match found, no need to check remaining patterns for this record

def main():
    """
    Main function that handles command-line arguments and orchestrates the vault reading process.
    
    Command-line arguments:
        -f, --file: Required. Path to the Ansible Vault encrypted CSV file
        -s, --search: Optional. Search patterns separated by '|' for filtering records
        -i, --ignore-case: Optional. Enable case-insensitive search (used with --search)
        
    Environment variables:
        VAULT_PASSWORD: Required. Password for decrypting the vault file
        
    Exit codes:
        0: Success
        1: Error (missing environment variable or file operation failed)
    """
    # Set up command-line argument parsing
    parser = argparse.ArgumentParser(description="Read Ansible Vault CSV")
    parser.add_argument("-f", "--file", required=True, help="Path to Vault file")
    parser.add_argument("-s", "--search", help="Search string for field1 (use '|' to separate multiple patterns)")
    parser.add_argument("-i", "--ignore-case", action="store_true", help="Case-insensitive search")
    args = parser.parse_args()

    # Get vault password from environment variable
    vault_password = os.environ.get("VAULT_PASSWORD")
    if not vault_password:
        print("Error: VAULT_PASSWORD environment variable not set.", file=sys.stderr)
        sys.exit(1)

    # Attempt to load and decrypt the vault file
    try:
        records = load_vault(args.file, vault_password)
    except Exception as e:
        print(f"Failed to load vault: {e}", file=sys.stderr)
        sys.exit(1)

    # Process records based on whether search was requested
    if args.search:
        # Search mode: filter and display matching records
        search_records(records, args.search, case_insensitive=args.ignore_case)
    else:
        # Display mode: show all records
        for fields in records:
            print(" ~ ".join(fields))

if __name__ == "__main__":
    # Entry point - only run main() if script is executed directly
    main()
