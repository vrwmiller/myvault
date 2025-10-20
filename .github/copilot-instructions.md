# Copilot Instructions

## Purpose
This repository contains GetVault, a command-line utility for decrypting and searching through Ansible Vault encrypted CSV files. The tool is designed for secure credential management and data retrieval from tilde-separated vault files. Focus on security best practices, robust error handling, and maintainable code when suggesting improvements or additions.

## Secrets & configuration
- Never hard-code vault passwords or sensitive data in code or examples.
- Use environment variables for credentials (example names below):
  - VAULT_PASSWORD (required for decrypting Ansible vault files)
- Handle vault passwords securely - read from environment, never log or store in plaintext.
- Ensure error messages don't leak sensitive information or vault contents.
- When working with encrypted data, process in memory without creating temporary files.

## Project Conventions
- Python scripts use the `.py` extension and follow a 4 whitespace indentation style.
- Emojis aren't used in code files, documentation, or comments.
- Code is commented using docstrings and inline comments where necessary.
- The project uses a `requirements.txt` file to manage Python dependencies.
- The main script for user interaction is `getvault.py`.
- CSV format expected is tilde-separated values: `field1~field2~field3`.

## Key Workflows
* Run locally:
    ```bash
    python3 -m venv venv && source venv/bin/activate
    python3 -m pip install --upgrade pip
    pip3 install -r requirements.txt
    ```
* Test the application:
    ```bash
    source venv/bin/activate
    python run_tests.py
    # Or run specific tests
    python -m pytest tests/ -v
    ```
* Use the tool:
    ```bash
    export VAULT_PASSWORD="your_vault_password"
    python getvault.py -f vault_file.csv -s "search_pattern"
    ```

## Performance & efficiency
- Optimize for memory usage when processing large vault files.
- Use efficient string operations for CSV parsing and pattern matching.
- Minimize file I/O operations and process data in memory when possible.
- Consider lazy loading for very large datasets if needed in the future.

## Security & privacy
- Never write or store vault passwords in the repository, logs, or error messages.
- When logging user content or responses, mask or redact sensitive vault data before persisting logs.
- Ensure decrypted vault contents are only processed in memory and never written to disk.
- Use secure practices when handling Ansible vault operations and credentials.
- Validate input data and handle edge cases to prevent security vulnerabilities.

## Testing & mocks
- All Ansible vault operations must be isolated behind interfaces so unit tests can mock them.
- Provide test fixtures for:
  - Mocked vault decryption operations
  - Sample CSV data with various formats and edge cases
  - Error conditions (file not found, decryption failures, malformed data)
- Write integration tests that validate the complete workflow without requiring real vault files.
- Use deterministic test data and mock Ansible vault components to ensure consistent test results.
- Test edge cases like empty files, invalid CSV formats, and special characters in data.
