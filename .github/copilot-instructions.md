## Pull Request Description Guidelines

- For simple code changes and PRs, use concise, direct descriptions.
- For larger or more complex PRs, provide detailed, high-quality descriptions that summarize:
  - The main changes and rationale
  - Any important context, design decisions, or breaking changes
  - Testing steps or validation performed
- Use bullet points, lists, and clear formatting for readability in large PRs.
- If in doubt, err on the side of more detail for reviewers.

# Copilot Instructions

## Purpose
This repository contains MyVault, a JSON-based Ansible Vault secret manager. The tool provides comprehensive CRUD operations for managing encrypted credential stores with property-based queries and secure password handling. Focus on security best practices, robust error handling, and maintainable code when suggesting improvements or additions.

## Secrets & configuration
- Never hard-code vault passwords or sensitive data in code or examples.
- Use environment variables for credentials (example names below):
  - VAULT_PASSWORD (optional for decrypting Ansible vault files - will prompt if not set)
- Handle vault passwords securely - read from environment or prompt interactively, never log or store in plaintext.
- Ensure error messages don't leak sensitive information or vault contents.
- When working with encrypted data, process in memory without creating temporary files.

## Project Conventions
- Emojis aren't used in code files, documentation, or comments.
- Python scripts use the .py extension and follow a 4 whitespace indentation style.
- Code is commented using docstrings and inline comments where necessary.
- The project uses a requirements.txt file to manage Python dependencies.
- The main script for user interaction is myvault.py.
- JSON format expected for vault contents with "property" field as primary key.

## GPG Commit Signing
- All contributors must make every effort to sign their git commits using a GPG key.
- Signed commits help verify authorship and improve repository security.
- Unsigned commits may be flagged during code review and should be avoided unless absolutely necessary.

### Setup Instructions
1. Generate a GPG key if you do not have one:
  ```bash
  gpg --full-generate-key
  ```
2. List your GPG keys:
  ```bash
  gpg --list-secret-keys --keyid-format LONG
  ```
3. Configure git to use your signing key:
  ```bash
  git config --global user.signingkey <YOUR_KEY_ID>
  git config --global commit.gpgsign true
  ```
4. Optionally, add your public key to your GitHub account for verified signatures.

### Testing GPG Signing
To verify that commit signing works:
1. Make a test commit with signing:
  ```bash
  echo "# GPG signing test" > gpg-sign-test.txt
  git add gpg-sign-test.txt
  git commit -S -m "test: verify GPG commit signing"
  ```
2. Check the commit signature:
  ```bash
  git log --show-signature -1
  ```
3. On GitHub, look for the "Verified" badge on your commit or PR.

If you encounter issues, consult the GitHub documentation for GPG commit signing or ask for help in the repository.

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
    python myvault.py -f vault_file.json -r --property "search_pattern"
    ```

## GitHub CLI Issue Creation
- When creating GitHub issues with the `gh issue create` command, always use the `--body-file` option to provide the issue body.
- This prevents shell quoting errors and ensures multi-line, formatted, or code block content is handled correctly.
- Example workflow:
  1. Write your issue body to a file, e.g. `issue.txt`.
  2. Run:
    ```bash
    gh issue create --title "Your Issue Title" --body-file issue.txt
    ```
- Do not paste multi-line issue bodies directly into the shell, as this can cause quoting errors and accidental command execution.
- This rule applies to both manual and automated workflows.

## Performance & efficiency
- Optimize for memory usage when processing large vault files.
- Use efficient string operations for JSON parsing and pattern matching.
- Minimize file I/O operations and process data in memory when possible.
- Consider lazy loading for very large datasets if needed in the future.

## Security & privacy
- Never write or store vault passwords in the repository, logs, or error messages.
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
