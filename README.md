# myvault

A comprehensive JSON-based Ansible Vault secret manager with property-based queries and secure CRUD operations.

## Quick Start

1. **Clone and setup**:
   ```bash
   git clone https://github.com/vrwmiller/myvault.git
   cd myvault
   python3 -m venv venv
   source environment.sh
   ```

2. **Create your first vault**:
   ```bash
   # Create JSON input file
   echo '[{"property": "website1.com", "username": "user@domain.com", "password": "secret123"}]' > secrets.json
   
   # Create encrypted vault - choose ONE password option:
   
   # Option A: Set password via environment variable (recommended for scripts)
   export VAULT_PASSWORD="your_secure_vault_password"
   python3 myvault.py -f vault.json create -i secrets.json
   
   # Option B: Interactive prompt (recommended for manual use)
   python3 myvault.py -f vault.json create -i secrets.json
   # Will prompt: "Enter Ansible Vault password: "
   
   # Option C: Let environment.sh help set it up (from Step 1)
   # The environment script can optionally configure vault password for the session
   ```

   **Password Priority**: Options are mutually exclusive - myvault uses environment variable if set, otherwise prompts interactively.

3. **Read from vault**:
   ```bash
   # Read all entries
   python3 myvault.py -f vault.json read
   
   # Search with patterns
   python3 myvault.py -f vault.json read --property "web*"
   ```

## Features

- **Complete CRUD operations**: Create, read, update, and delete vault entries
- **JSON-based storage**: Modern extensible schema with arbitrary properties
- **Property-based organization**: Each entry identified by a unique property field  
- **Advanced search capabilities**: Glob patterns and pipe-separated alternatives
- **Interactive password prompting**: Secure password input with fallback to environment variables
- **Data validation**: Built-in JSON structure and file permission validation
- **Security logging**: Comprehensive logging with sensitive data masking

## Documentation

| Topic | Description | Link |
|-------|-------------|------|
| **Installation** | Complete setup guide with environment management | [docs/INSTALLATION.md](docs/INSTALLATION.md) |
| **Examples** | Usage patterns, scripting examples, and workflows | [docs/EXAMPLES.md](docs/EXAMPLES.md) |
| **API Reference** | Command syntax, options, and JSON schema | [docs/API.md](docs/API.md) |
| **Development** | Contributing, testing, and development workflow | [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) |
## Essential Commands

```bash
# Validate JSON input
python3 myvault.py validate -i secrets.json

# Create vault from JSON
python3 myvault.py -f vault.json create -i secrets.json

# Read all entries
python3 myvault.py -f vault.json read

# Search with patterns
python3 myvault.py -f vault.json read --property "web*|*api*"

# Update entries
python3 myvault.py -f vault.json update -i updates.json

# Delete entries
python3 myvault.py -f vault.json delete --property "test.*" --force
```

## JSON Schema

Each vault entry requires a `property` field and supports arbitrary additional fields:

```json
[
    {
        "property": "website1.com",
        "username": "user@domain.com", 
        "password": "secret123",
        "notes": "Additional notes"
    }
]
```

## Contributing

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Make your changes with appropriate tests
4. Ensure all tests pass (`python3 run_tests.py`)
5. Submit a pull request

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.