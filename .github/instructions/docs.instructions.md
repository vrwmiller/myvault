---
applyTo: "docs/**"
---

# Docs Agent Instructions

## Documentation structure
```
docs/
  API.md          — Command reference and JSON schema
  DEVELOPMENT.md  — Dev setup, test commands, security tooling
  EXAMPLES.md     — Usage examples with sample vault operations
  INSTALLATION.md — Prerequisites and setup steps
```

## Source of truth
- CLI interface and all command options are defined in `myvault.py` (`argparse` setup near end of file)
- JSON schema: every entry requires `property` (string, non-empty); all other fields are arbitrary key/value pairs
- Supported commands: `validate`, `read`, `create`, `update`, `delete`
- Global flags: `-f/--file` (vault file path), `-d/--debug` (console logging)

## Style conventions
- No emojis in documentation
- Use fenced code blocks with `bash` or `json` language tags
- Passwords and vault contents are never shown in real form — use placeholder values like `"your_vault_password"` or `"secret123"`
- Environment variable for vault password: `VAULT_PASSWORD` (optional — tool will prompt if unset)
- File permission requirement for vault files: `600` (`-rw-------`)

## Keeping docs accurate
- When a command's flags change in `myvault.py`, update `docs/API.md` to match
- When setup steps change (new dependency, new env var), update `docs/INSTALLATION.md`
- When new test or security tooling is added, update `docs/DEVELOPMENT.md`
- `docs/EXAMPLES.md` should show realistic end-to-end workflows, not just flag listings

## Example format (EXAMPLES.md)
Show a realistic scenario with setup context, then the command, then expected output:
```bash
export VAULT_PASSWORD="your_vault_password"

# Read all entries matching a glob
python3 myvault.py -f vault.json read --property "web*"

# Output:
# property: website1.com
# username: user@example.com
# password: secret123
```
