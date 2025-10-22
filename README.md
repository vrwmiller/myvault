# MyVault

A comprehensive JSON-based Ansible Vault secret manager with property-based queries and secure CRUD operations.

## Overview

MyVault is a sophisticated Python utility for managing Ansible Vault encrypted JSON files. It provides comprehensive CRUD operations for encrypted credential stores with property-based organization and secure password handling.

## Features

- **Complete CRUD operations**: Create, read, update, and delete vault entries
- **JSON-based storage**: Modern extensible schema with arbitrary properties
- **Property-based organization**: Each entry identified by a unique property field  
- **Advanced search capabilities**: Glob patterns and pipe-separated alternatives
- **Interactive password prompting**: Secure password input with fallback to environment variables
- **Data validation**: Built-in JSON structure and file permission validation
- **Security logging**: Comprehensive logging with sensitive data masking
- **Interactive confirmations**: Safety prompts for destructive operations

## Installation

### Prerequisites

- Python 3.6 or higher
- `venv` module (included with Python 3.3+)

### Setup

1. Clone the repository:

   ```bash
   git clone https://github.com/vrwmiller/myvault.git
   cd myvault
   ```

2. Create and activate a virtual environment:

   ```bash
   # Create virtual environment
   python3 -m venv venv
   
   # Activate virtual environment
   source venv/bin/activate  # macOS/Linux
   # venv\Scripts\activate   # Windows
   ```

3. Install dependencies:

   ```bash
   pip3 install -r requirements.txt
   ```

4. Make script executable (optional):

   ```bash
   chmod +x myvault.py run_tests.py
   ```

### Virtual Environment Management

After initial setup, you'll need to activate the virtual environment each time you use the tool:

```bash
# Navigate to project directory
cd myvault

# Activate virtual environment
source venv/bin/activate  # macOS/Linux
# venv\Scripts\activate   # Windows

# Use the tool
python3 myvault.py -f your_vault_file.json read

# Deactivate when done (optional)
deactivate
```

## Usage

### Password Management

MyVault supports flexible password input:

- **Environment variable** (recommended for automation):

  ```bash
  export VAULT_PASSWORD="your_vault_password_here"
  python3 myvault.py -f vault.json read
  ```

- **Interactive prompting** (secure for manual use):

  ```bash
  python3 myvault.py -f vault.json read
  # Will prompt: Enter Ansible Vault password: 
  ```

### Command Reference

#### Global Options

```text
python3 myvault.py [-f VAULT_FILE] [-d] {validate,read,create,update,delete} ...
```

**Global Arguments:**

- `-f, --file`: Path to the encrypted vault file (required for most commands)
- `-d, --debug`: Enable debug logging to console

**Subcommands:**

- `validate`: Validate JSON input file structure and permissions
- `read`: Read entries from vault file
- `create`: Create new vault entries from JSON input
- `update`: Update existing vault entries from JSON input
- `delete`: Delete vault entries by property

#### JSON Schema

MyVault uses an extensible JSON schema where each entry requires a `property` field and supports arbitrary additional fields:

```json
[
    {
        "property": "website1.com",
        "username": "user@domain.com",
        "password": "secret123",
        "apitoken": "optional_token",
        "notes": "Any additional notes"
    },
    {
        "property": "database.server",
        "username": "dbadmin",
        "password": "dbpass789",
        "host": "db.internal.com",
        "port": "5432",
        "ssl": true,
        "notes": "Production database"
    }
]
```

## Examples

### Basic Operations

#### Validate JSON input file

```bash
python3 myvault.py validate -i secrets.json
```

#### Create new vault from JSON

```bash
python3 myvault.py -f vault.json create -i new_secrets.json
```

#### Read all entries (with sensitive fields masked)

```bash
python3 myvault.py -f vault.json read
```

#### Read specific property

```bash
python3 myvault.py -f vault.json read --property website1.com
```

### Advanced Property Queries

#### Glob patterns

```bash
# Match properties starting with 'web'
python3 myvault.py -f vault.json read --property "web*"

# Match properties ending with '.com'
python3 myvault.py -f vault.json read --property "*.com"
```

#### Multiple patterns with pipe separation

```bash
# Match web domains, APIs, or databases
python3 myvault.py -f vault.json read --property "web*|*api*|database.*"

# Match .com domains, databases, or FTP servers
python3 myvault.py -f vault.json read --property "*.com|database.*|ftp.*"
```

### Modification Operations

#### Update entries from JSON file

```bash
python3 myvault.py -f vault.json update -i updates.json
```

#### Delete entry with confirmation

```bash
python3 myvault.py -f vault.json delete --property website1.com
```

#### Delete with expressions and force mode

```bash
# Delete all test entries without confirmation
python3 myvault.py -f vault.json delete --property "test.*" --force

# Delete multiple patterns
python3 myvault.py -f vault.json delete --property "*.old|temp.*"
```

## Security Features

- **File permissions validation**: Ensures vault files have secure 600 permissions
- **Sensitive data masking**: Passwords and tokens are masked in output by default
- **Secure password input**: Uses getpass for hidden password entry
- **Memory-only processing**: Decrypted data never written to temporary files
- **Comprehensive logging**: All operations logged with sensitive data redacted

## Development

### Running Tests

```bash
# Activate virtual environment
source venv/bin/activate

# Run all tests
python3 run_tests.py

# Run specific test modules
python3 -m pytest tests/test_myvault.py -v

# Run with coverage
python3 -m pytest tests/ --cov=myvault --cov-report=html
```

### Test Structure

- `tests/test_myvault.py` - Main test suite with unit and integration tests
- `run_tests.py` - Test runner with coverage reporting
- All vault operations are mocked for security and deterministic results

### Project Structure

```
myvault/
├── myvault.py          # Main application script
├── requirements.txt    # Python dependencies
├── run_tests.py       # Test runner
├── tests/             # Test suite
│   └── test_myvault.py
├── examples/          # Example files and usage
└── .github/           # GitHub configuration
    └── copilot-instructions.md
```

## Contributing

1. Fork the repository
2. Create a feature branch
3. Make your changes with appropriate tests
4. Ensure all tests pass
5. Submit a pull request

## License

This project is licensed under the MIT License - see the LICENSE file for details.