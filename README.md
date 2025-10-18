# GetVault

A command-line utility for decrypting and searching Ansible Vault encrypted CSV files with tilde-separated values.

## Overview

GetVault is a Python tool designed to work with Ansible Vault encrypted CSV files that use tilde (`~`) as field separators. It provides functionality to decrypt vault files and search through records based on patterns in the first field.

## Features

- **Decrypt Ansible Vault files**: Safely decrypt vault-encrypted CSV data
- **Pattern-based searching**: Search for specific patterns in the first field of records
- **Multiple pattern support**: Use pipe (`|`) separated patterns for complex searches
- **Case-insensitive search**: Optional case-insensitive pattern matching
- **Clean output formatting**: Well-formatted output with tilde-separated fields

## Installation

### Prerequisites

- Python 3.6 or higher
- `venv` module (included with Python 3.3+)

### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/vrwmiller/getvault.git
   cd getvault
   ```

2. Create and activate a virtual environment:

   ```bash
   # Create virtual environment
   python -m venv venv
   
   # Activate virtual environment
   # On macOS/Linux:
   source venv/bin/activate
   
   # On Windows:
   # venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip install -r requirements.txt
   ```

4. Make the script executable (optional):

   ```bash
   chmod +x getvault.py
   ```

### Virtual Environment Management

After initial setup, you'll need to activate the virtual environment each time you use the tool:

```bash
# Navigate to project directory
cd getvault

# Activate virtual environment
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate   # Windows

# Use the tool
python getvault.py -f your_vault_file.csv

# Deactivate when done (optional)
deactivate
```

## Usage

### Environment Setup

Before using GetVault, you must set the vault password as an environment variable:

```bash
export VAULT_PASSWORD="your_vault_password_here"
```

### Command Line Options

```text
python getvault.py -f VAULT_FILE [-s SEARCH_PATTERNS] [-i]
```

#### Required Arguments

- `-f, --file`: Path to the Ansible Vault encrypted CSV file

#### Optional Arguments

- `-s, --search`: Search patterns for the first field (use `|` to separate multiple patterns)
- `-i, --ignore-case`: Enable case-insensitive search

### Examples

#### Display all records

```bash
python getvault.py -f secrets.vault
```

#### Search for a single pattern

```bash
python getvault.py -f secrets.vault -s "database"
```

#### Search for multiple patterns

```bash
python getvault.py -f secrets.vault -s "database|api|token"
```

#### Case-insensitive search

```bash
python getvault.py -f secrets.vault -s "Database" -i
```

### Expected File Format

The vault file should contain CSV data with exactly three fields separated by tildes (`~`):

```text
field1~field2~field3
database_host~db.example.com~Database server hostname
api_key~abc123def456~Production API key
admin_token~xyz789uvw012~Administrative access token
```

## Output Format

Records are displayed with fields separated by ` ~ ` (space-tilde-space):

```text
database_host ~ db.example.com ~ Database server hostname
api_key ~ abc123def456 ~ Production API key
```

## Error Handling

The script handles several error conditions:

- **Missing vault password**: Exits with code 1 if `VAULT_PASSWORD` environment variable is not set
- **File access errors**: Exits with code 1 if the vault file cannot be read or decrypted
- **Malformed records**: Silently skips records that don't have exactly three fields

## Security Considerations

- **Environment variables**: The vault password is read from an environment variable to avoid exposing it in command history
- **Memory handling**: Sensitive data is processed in memory and not written to temporary files
- **Ansible compatibility**: Uses official Ansible vault libraries for secure decryption
- **Dependency isolation**: Virtual environment ensures clean, isolated dependency management without affecting system Python packages

## Development

### Project Structure

```text
getvault/
├── getvault.py          # Main application script
├── requirements.txt     # Python dependencies
├── venv/               # Virtual environment (created during setup)
└── README.md           # Project documentation
```

### Development Setup

For development work, follow the same virtual environment setup:

1. Clone and set up the project:

   ```bash
   git clone https://github.com/vrwmiller/getvault.git
   cd getvault
   python -m venv venv
   source venv/bin/activate  # macOS/Linux
   pip install -r requirements.txt
   ```

2. Make your changes and test:

   ```bash
   # Ensure virtual environment is active
   source venv/bin/activate
   
   # Run the script with test data
   python getvault.py -f test_vault.csv
   ```

### Code Style

The project follows Python best practices:

- Comprehensive docstrings for all functions
- Type hints in function signatures
- Detailed inline comments
- Error handling with appropriate exit codes
- Virtual environment isolation for dependencies

### Contributing

1. Fork the repository
2. Create a feature branch: `git checkout -b feature-name`
3. Set up virtual environment: `python -m venv venv && source venv/bin/activate`
4. Install dependencies: `pip install -r requirements.txt`
5. Make your changes and add tests if applicable
6. Commit your changes: `git commit -am 'Add feature'`
7. Push to the branch: `git push origin feature-name`
8. Submit a pull request

## License

This project is available under the MIT License. See the LICENSE file for more details.

## Support

For issues, questions, or contributions, please use the GitHub issue tracker.

---

**Note**: This tool is designed specifically for Ansible Vault encrypted files with tilde-separated CSV format. For other formats or encryption methods, modifications to the parsing logic may be required.