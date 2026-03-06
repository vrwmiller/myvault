# Examples and Usage Patterns

## Basic Operations

### Validate JSON input file

```bash
python3 myvault.py validate -i secrets.json
```

### Create new vault from JSON

```bash
python3 myvault.py -f vault.json create -i new_secrets.json
```

### Read all entries

```bash
python3 myvault.py -f vault.json read
```

### Read specific property

```bash
python3 myvault.py -f vault.json read --property website1.com
```

## Advanced Property Queries

### Glob patterns

```bash
# Match properties starting with 'web'
python3 myvault.py -f vault.json read --property "web*"

# Match properties ending with '.com'
python3 myvault.py -f vault.json read --property "*.com"
```

### Multiple patterns with pipe separation

```bash
# Match web domains, APIs, or databases
python3 myvault.py -f vault.json read --property "web*|*api*|database.*"

# Match .com domains, databases, or FTP servers
python3 myvault.py -f vault.json read --property "*.com|database.*|ftp.*"
```

## Modification Operations

### Update entries from JSON file

```bash
python3 myvault.py -f vault.json update -i updates.json
```

### Delete entry with confirmation

```bash
python3 myvault.py -f vault.json delete --property website1.com
```

### Delete with expressions and force mode

```bash
# Delete all test entries without confirmation
python3 myvault.py -f vault.json delete --property "test.*" --force

# Delete multiple patterns
python3 myvault.py -f vault.json delete --property "*.old|temp.*"
```

### Edit vault interactively

```bash
# Open vault in default editor ($EDITOR, or vi if unset)
python3 myvault.py -f vault.json edit

# Open vault in a specific editor
python3 myvault.py -f vault.json edit --editor nano

# Use a GUI editor
python3 myvault.py -f vault.json edit --editor "code --wait"
```

## Pipeline and Scripting Usage

### Output Formats

myvault supports three output formats via `--format`:

- `pipe` (default): space-pipe-space separated, one entry per line
- `json`: JSON array to stdout
- `raw`: single field value per matching entry, one per line

#### pipe format — extract specific fields with shell tools

```bash
# Extract password field (3rd column in pipe format)
python3 myvault.py -f vault.json read --property "website1.com" | awk -F' \| ' '{print $3}'

# Extract username field
python3 myvault.py -f vault.json read --property "website1.com" | awk -F' \| ' '{print $2}'
```

#### raw format — extract a single field directly (recommended for scripting)

```bash
# Extract password directly — no parsing needed
python3 myvault.py -f vault.json read --property "website1.com" --format raw --field password

# Capture into a variable
DB_PASS=$(python3 myvault.py -f vault.json read --property "database.prod" --format raw --field password)

# Use in curl
curl -H "Authorization: Bearer $(python3 myvault.py -f vault.json read --property "api.token" --format raw --field apitoken)" \
     https://api.example.com/data

# Use with sshpass
sshpass -p "$(python3 myvault.py -f vault.json read --property "server1.ssh" --format raw --field password)" \
        ssh user@server1.com

# Use with mysql
mysql -u admin -p"$(python3 myvault.py -f vault.json read --property "mysql.admin" --format raw --field password)" mydb
```

#### json format — machine-readable output

```bash
# Output as JSON array
python3 myvault.py -f vault.json read --property "web*" --format json

# Pipe to jq for further processing
python3 myvault.py -f vault.json read --property "web*" --format json | jq '.[].property'
```

#### Export operations

```bash
# Export search results to a JSON file
python3 myvault.py -f vault.json read --property "web*" -o results.json
```

## Password Management Examples

### Environment variable (recommended for automation)

```bash
export VAULT_PASSWORD="your_vault_password_here"
python3 myvault.py -f vault.json read
```

### Interactive prompting (secure for manual use)

```bash
python3 myvault.py -f vault.json read
# Will prompt: Enter Ansible Vault password: 
```

## Complex Scenarios

### Bulk Operations

```bash
# Create multiple entries from a large JSON file
python3 myvault.py -f production_vault.json create -i bulk_secrets.json

# Update multiple entries with pattern matching
python3 myvault.py -f vault.json read --property "staging.*" -o staging_backup.json
python3 myvault.py -f vault.json update -i updated_staging.json

# Delete old test entries
python3 myvault.py -f vault.json delete --property "*test*|*staging*|*temp*" --force
```

### Cross-Environment Management

```bash
# Copy production secrets to staging vault
python3 myvault.py -f prod_vault.json read --property "database.*" -o db_secrets.json
python3 myvault.py -f staging_vault.json create -i db_secrets.json

# Migrate from old vault format
python3 myvault.py validate -i legacy_vault.json
python3 myvault.py -f new_vault.json create -i legacy_vault.json
```

### Security Best Practices

```bash
# Always validate before importing
python3 myvault.py validate -i untrusted_input.json

# Use force mode only when certain
python3 myvault.py -f vault.json delete --property "*.temp" --force

# Export with output redirection for sensitive operations
python3 myvault.py -f vault.json read --property "critical.*" > /dev/null 2>&1
```

## Troubleshooting Common Issues

### File Permissions

```bash
# Fix vault file permissions
chmod 600 vault.json

# Verify file is encrypted
file vault.json  # Should show: ASCII text
head -1 vault.json  # Should start with: $ANSIBLE_VAULT;1.1;AES256
```

### Debug Mode

```bash
# Enable debug logging for troubleshooting
python3 myvault.py -d -f vault.json read --property "problematic.entry"
```

### Backup and Recovery

```bash
# Create backup before major operations
cp vault.json vault_backup_$(date +%Y%m%d).json

# Export all entries as plain JSON backup
python3 myvault.py -f vault.json read -o backup_$(date +%Y%m%d).json
```