#!/usr/bin/env python3
import os
import sys
import argparse
from ansible.constants import DEFAULT_VAULT_ID_MATCH
from ansible.parsing.vault import VaultSecret, VaultLib

def load_vault(file_path, password):
    """Load Ansible Vault CSV and return cleaned records."""
    secret = VaultSecret(password.encode())
    vault = VaultLib([(DEFAULT_VAULT_ID_MATCH, secret)])
    with open(file_path, 'rb') as f:
        encrypted_data = f.read()
    decrypted_data = vault.decrypt(encrypted_data)
    lines = decrypted_data.decode('utf-8').splitlines()
    records = []
    for line in lines:
        fields = [field.strip() for field in line.split('~')]
        if len(fields) == 3:
            records.append(fields)
    return records

def search_records(records, search_patterns, case_insensitive=True):
    """
    Print all three fields for records where field1 matches any pattern.
    `search_patterns` is a string like 'pattern1|pattern2|pattern3'.
    """
    patterns = [p.strip() for p in search_patterns.split('|') if p.strip()]
    for fields in records:
        field1 = fields[0]
        check_field = field1.lower() if case_insensitive else field1
        for pattern in patterns:
            pat = pattern.lower() if case_insensitive else pattern
            if pat in check_field:
                print(" ~ ".join(fields))
                break  # match found, no need to check remaining patterns

def main():
    parser = argparse.ArgumentParser(description="Read Ansible Vault CSV")
    parser.add_argument("-f", "--file", required=True, help="Path to Vault file")
    parser.add_argument("-s", "--search", help="Search string for field1 (use '|' to separate multiple patterns)")
    parser.add_argument("-i", "--ignore-case", action="store_true", help="Case-insensitive search")
    args = parser.parse_args()

    vault_password = os.environ.get("VAULT_PASSWORD")
    if not vault_password:
        print("Error: VAULT_PASSWORD environment variable not set.", file=sys.stderr)
        sys.exit(1)

    try:
        records = load_vault(args.file, vault_password)
    except Exception as e:
        print(f"Failed to load vault: {e}", file=sys.stderr)
        sys.exit(1)

    if args.search:
        search_records(records, args.search, case_insensitive=args.ignore_case)
    else:
        # Print all records
        for fields in records:
            print(" ~ ".join(fields))

if __name__ == "__main__":
    main()
