# API Reference

## Command Reference

### Global Options

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

## JSON Schema

myvault uses an extensible JSON schema where each entry requires a `property` field and supports arbitrary additional fields:

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

## Command Details

### validate

Validates JSON input file structure and permissions without accessing any vault files.

**Syntax:**
```bash
python3 myvault.py validate -i INPUT_FILE
```

**Arguments:**
- `-i, --input`: Path to JSON file to validate

**Example:**
```bash
python3 myvault.py validate -i secrets.json
```

### read

Reads and displays entries from an encrypted vault file.

**Syntax:**
```bash
python3 myvault.py -f VAULT_FILE read [--property PATTERN] [-o OUTPUT_FILE]
```

**Arguments:**
- `--property`: Property pattern to match (supports glob patterns and pipe separation)
- `-o, --output`: Output file path for JSON export

**Property Pattern Syntax:**
- `website1.com` - Exact match
- `web*` - Starts with "web"
- `*.com` - Ends with ".com"
- `web*|*api*` - Multiple patterns with pipe separation

**Examples:**
```bash
# Read all entries
python3 myvault.py -f vault.json read

# Read specific property
python3 myvault.py -f vault.json read --property website1.com

# Read with glob pattern
python3 myvault.py -f vault.json read --property "web*"

# Read multiple patterns
python3 myvault.py -f vault.json read --property "web*|*api*"

# Export to JSON
python3 myvault.py -f vault.json read --property "web*" -o results.json
```

### create

Creates new entries in a vault file from JSON input.

**Syntax:**
```bash
python3 myvault.py -f VAULT_FILE create -i INPUT_FILE
```

**Arguments:**
- `-i, --input`: Path to JSON file containing new entries

**Behavior:**
- Creates vault file if it doesn't exist
- Adds new entries to existing vault
- Fails if property already exists (use `update` to modify existing entries)

**Example:**
```bash
python3 myvault.py -f vault.json create -i new_secrets.json
```

### update

Updates existing entries in a vault file from JSON input.

**Syntax:**
```bash
python3 myvault.py -f VAULT_FILE update -i INPUT_FILE
```

**Arguments:**
- `-i, --input`: Path to JSON file containing updated entries

**Behavior:**
- Updates entries that match by `property` field
- Skips entries that don't exist in vault
- Merges new fields with existing entries

**Example:**
```bash
python3 myvault.py -f vault.json update -i updates.json
```

### delete

Deletes entries from a vault file by property pattern.

**Syntax:**
```bash
python3 myvault.py -f VAULT_FILE delete --property PATTERN [--force]
```

**Arguments:**
- `--property`: Property pattern to match for deletion
- `--force`: Skip confirmation prompts

**Behavior:**
- Prompts for confirmation unless `--force` is used
- Supports same pattern syntax as `read` command
- Shows entries to be deleted before confirmation

**Examples:**
```bash
# Delete with confirmation
python3 myvault.py -f vault.json delete --property website1.com

# Delete pattern with force
python3 myvault.py -f vault.json delete --property "test.*" --force

# Delete multiple patterns
python3 myvault.py -f vault.json delete --property "*.old|temp.*" --force
```

## Output Formats

### Standard Output

Default output format is pipe-separated for easy parsing:

```
property | username | password | field1 | field2 | ...
```

**Example:**
```
website1.com | user@domain.com | secret123 | api_token_value | Additional notes
```

### JSON Output

When using `-o` flag, output is formatted as JSON array:

```json
[
    {
        "property": "website1.com",
        "username": "user@domain.com",
        "password": "secret123",
        "apitoken": "api_token_value",
        "notes": "Additional notes"
    }
]
```

## Pattern Matching

### Glob Patterns

- `*` - Matches any characters
- `?` - Matches single character
- `[abc]` - Matches any character in brackets
- `[!abc]` - Matches any character not in brackets

### Pipe Separation

Multiple patterns can be combined with `|`:

```bash
--property "web*|*api*|database.*"
```

This matches any property that:
- Starts with "web", OR
- Contains "api", OR  
- Starts with "database."

## Environment Variables

### VAULT_PASSWORD

Set the vault password to avoid interactive prompts:

```bash
export VAULT_PASSWORD="your_vault_password"
python3 myvault.py -f vault.json read
```

**Security Note:** Be careful when setting passwords in environment variables, especially in shared environments.

## Exit Codes

- `0` - Success
- `1` - General error (file not found, permission denied, etc.)
- `2` - Validation error (invalid JSON, missing required fields)
- `3` - Vault operation error (decryption failed, incorrect password)

## File Security

### Vault File Permissions

Vault files should have restricted permissions:

```bash
chmod 600 vault.json  # Read/write for owner only
```

### Input File Validation

Before processing, myvault validates:

- JSON syntax and structure
- Required `property` field in each entry
- File permissions (warns if too permissive)
- Data types and encoding

## Error Handling

### Common Error Messages

**"Vault file not found"**
- File path is incorrect
- File doesn't exist
- Permission denied

**"Invalid JSON format"**
- Syntax error in JSON input
- Invalid UTF-8 encoding
- Missing required fields

**"Decryption failed"**
- Incorrect vault password
- Corrupted vault file
- Wrong vault format

**"Property already exists"**
- Use `update` instead of `create`
- Or delete existing entry first

### Debug Mode

Enable detailed logging with `-d` flag:

```bash
python3 myvault.py -d -f vault.json read --property "problematic.entry"
```

This provides:
- Detailed operation logs
- File access information
- Pattern matching details
- Error stack traces (when applicable)