# GetVault

A command-line utility for decrypting and searching Ansible Vault encrypted files with both CSV (tilde-separated) and JSON formats.

## Overview

GetVault is a Python tool suite designed to work with Ansible Vault encrypted data files. It provides two main utilities:

- **`getvault.py`**: For traditional CSV files with tilde-separated values
- **`myvault.py`**: For modern JSON files with extensible property-based schemas

## Features

### GetVault (CSV Format)

- **Decrypt Ansible Vault files**: Safely decrypt vault-encrypted CSV data
- **Pattern-based searching**: Search for specific patterns in the first field of records
- **Multiple pattern support**: Use pipe (`|`) separated patterns for complex searches
- **Case-insensitive search**: Optional case-insensitive pattern matching
- **Clean output formatting**: Well-formatted output with tilde-separated fields

### MyVault (JSON Format)

- **CRUD operations**: Create, read, update, and delete vault entries
- **Extensible schema**: Support for arbitrary properties beyond standard fields
- **Property-based organization**: Each entry identified by a unique property field
- **Security logging**: Comprehensive logging with sensitive data masking
- **Data validation**: Built-in JSON structure and file permission validation
- **Interactive confirmation**: Safety prompts for destructive operations

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
   python3 -m venv venv
   
   # Activate virtual environment
   # On macOS/Linux:
   source venv/bin/activate
   
   # On Windows:
   # venv\Scripts\activate
   ```

3. Install dependencies:

   ```bash
   pip3 install -r requirements.txt
   ```

4. Make scripts executable (optional):

   ```bash
   chmod +x getvault.py run_tests.py
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
python3 getvault.py -f your_vault_file.csv

# Deactivate when done (optional)
deactivate
```

## Usage

### Environment Setup

Before using either tool, you must set the vault password as an environment variable:

```bash
export VAULT_PASSWORD="your_vault_password_here"
```

### GetVault (CSV) Usage

#### GetVault Command Options

```text
python3 getvault.py -f VAULT_FILE [-s SEARCH_PATTERNS] [-i]
```

##### Required Arguments

- `-f, --file`: Path to the Ansible Vault encrypted CSV file

##### Optional Arguments

- `-s, --search`: Search patterns for the first field (use `|` to separate multiple patterns)
- `-i, --ignore-case`: Enable case-insensitive search

#### GetVault Examples

##### Display all records

```bash
python3 getvault.py -f secrets.vault
```

##### Search for a single pattern

```bash
python3 getvault.py -f secrets.vault -s "database"
```

##### Search for multiple patterns

```bash
python3 getvault.py -f secrets.vault -s "database|api|token"
```

##### Case-insensitive search

```bash
python3 getvault.py -f secrets.vault -s "Database" -i
```

#### Expected File Format

The vault file should contain CSV data with exactly three fields separated by tildes (`~`):

```text
field1~field2~field3
database_host~db.example.com~Database server hostname
api_key~abc123def456~Production API key
admin_token~xyz789uvw012~Administrative access token
```

#### Output Format

Records are displayed with fields separated by ` ~ ` (space-tilde-space):

```text
database_host ~ db.example.com ~ Database server hostname
api_key ~ abc123def456 ~ Production API key
```

### MyVault (JSON) Usage

#### MyVault Command Options

```text
python3 myvault.py [-f VAULT_FILE] [-v] {validate,read,create,update,delete} ...
```

##### Global Arguments

- `-f, --file`: Path to the encrypted vault file (required for most commands)
- `-v, --verbose`: Enable verbose logging

##### Subcommands

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

#### MyVault Examples

##### Validate JSON input file

```bash
python3 myvault.py validate -i secrets.json
```

##### Create new vault from JSON

```bash
python3 myvault.py -f vault.json create -i new_secrets.json
```

##### Read all entries (with sensitive fields masked)

```bash
python3 myvault.py -f vault.json read
```

##### Read specific property

```bash
python3 myvault.py -f vault.json read --property website1.com
```

##### Read with property expressions

```bash
# Glob patterns - match properties starting with 'web'
python3 myvault.py -f vault.json read --property "web*"

# Multiple patterns with pipe separation
python3 myvault.py -f vault.json read --property "web*|*api*|database.*"

# Complex patterns - match .com domains, databases, or FTP servers
python3 myvault.py -f vault.json read --property "*.com|database.*|ftp.*"
```

##### Update entries from JSON file

```bash
python3 myvault.py -f vault.json update -i updates.json
```

##### Delete entry with confirmation

```bash
python3 myvault.py -f vault.json delete --property website1.com
```

##### Delete multiple entries with expressions

```bash
# Delete all entries ending with '.old'
python3 myvault.py -f vault.json delete --property "*.old"

# Delete multiple specific properties 
python3 myvault.py -f vault.json delete --property "test1|test2|test3"

# Delete with glob patterns and alternatives
python3 myvault.py -f vault.json delete --property "web*|*demo*|temp.*"
```

##### Force delete without confirmation

```bash
python3 myvault.py -f vault.json delete --property website1.com --force

# Force delete multiple entries without confirmation
python3 myvault.py -f vault.json delete --property "*.temp|*.old" --force
```

##### Save read output to file

```bash
python3 myvault.py -f vault.json read -o output.json
```

#### Property Expression Syntax

The `--property` argument in the `read` command supports powerful expression syntax for flexible filtering:

##### Exact Matching

```bash
--property "website1.com"  # Matches exactly "website1.com"
```

##### Glob Patterns

```bash
--property "web*"         # Matches anything starting with "web"
--property "*.com"        # Matches anything ending with ".com" 
--property "*api*"        # Matches anything containing "api"
--property "web?.com"     # Matches "web" + single character + ".com"
--property "web[0-9].com" # Matches "web" + digit + ".com"
```

##### Multiple Alternatives (Pipe Separation)

```bash
--property "site1|site2|site3"           # Exact matches for any of the three
--property "web*|*api*|database.*"       # Glob patterns with alternatives
--property "*.com|*.net|internal.*"      # Multiple domain patterns
```

##### Case Sensitivity

All property expressions are **case-insensitive**, so `"WEB*"` matches `"website1.com"`.

#### Security Features

- **File permissions**: Input JSON files must have secure permissions (600)
- **Sensitive data masking**: Passwords, tokens, and secrets are masked in display output
- **Confirmation prompts**: Destructive operations require user confirmation unless `--force` is used
- **Secure logging**: Log messages never expose sensitive vault contents
- **Memory-only processing**: Decrypted data is never written to temporary files

## Testing

The project includes a comprehensive test suite using pytest.

### Running Tests

#### Quick Test Run

```bash
# Activate virtual environment
source venv/bin/activate

# Run tests
python3 -m pytest tests/ -v
```

#### Using the Test Runner

```bash
# Run tests with coverage report
python3 run_tests.py
```

#### Manual pytest Options

```bash
# Run specific test class
python3 -m pytest tests/test_getvault.py::TestLoadVault -v

# Run with coverage
python3 -m pytest tests/ --cov=getvault --cov-report=html

# Run tests and stop on first failure
python3 -m pytest tests/ -x
```

### Test Coverage

The test suite covers:

- **Vault loading**: Mock Ansible vault decryption and CSV parsing
- **Search functionality**: Pattern matching with various edge cases
- **Error handling**: File not found, decryption errors, invalid data
- **Edge cases**: Empty files, malformed records, whitespace handling
- **Integration**: End-to-end workflow testing

### Test Files

- `tests/test_getvault.py` - Main test suite with unit and integration tests
- `tests/conftest.py` - Shared test fixtures and configuration
- `tests/__init__.py` - Test package initialization
- `run_tests.py` - Test runner script with coverage reporting
- `pytest.ini` - Pytest configuration

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
├── run_tests.py         # Test runner script
├── pytest.ini          # Pytest configuration
├── tests/              # Test directory
│   ├── __init__.py     # Test package initialization
│   ├── conftest.py     # Shared test fixtures and configuration
│   └── test_getvault.py # Unit test suite
├── venv/               # Virtual environment (created during setup)
└── README.md           # Project documentation
```

### Development Setup

For development work, follow the same virtual environment setup:

1. Clone and set up the project:

   ```bash
   git clone https://github.com/vrwmiller/getvault.git
   cd getvault
   python3 -m venv venv
   source venv/bin/activate  # macOS/Linux
   pip3 install -r requirements.txt
   ```

2. Make your changes and test:

   ```bash
   # Ensure virtual environment is active
   source venv/bin/activate
   
   # Run the test suite
   python3 run_tests.py
   
   # Run the script with test data
   python3 getvault.py -f test_vault.csv
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
3. Set up virtual environment: `python3 -m venv venv && source venv/bin/activate`
4. Install dependencies: `pip3 install -r requirements.txt`
5. Make your changes and add tests if applicable
6. Commit your changes: `git commit -am 'Add feature'`
7. Push to the branch: `git push origin feature-name`
8. Submit a pull request

## License

This project is available under the MIT License. See the LICENSE file for more details.

## Support

For issues, questions, or contributions, please use the GitHub issue tracker.

---

**Note**: These tools are designed specifically for Ansible Vault encrypted files. GetVault works with tilde-separated CSV format, while MyVault uses extensible JSON format. For other formats or encryption methods, modifications to the parsing logic may be required.
