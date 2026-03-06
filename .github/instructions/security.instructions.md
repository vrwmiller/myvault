---
applyTo: "myvault.py"
---

# Security Agent Instructions

## Security tool
Run `bandit -r myvault.py -ll` to perform static analysis. The `-ll` flag surfaces medium and high severity findings. The CI workflow (`ci.yml`) also runs bandit on every push.

## Non-negotiable rules (enforce on every review)
1. **No plaintext secrets in logs** — `logger.*` calls must never include password values, decrypted vault contents, or raw key material. Log the error type (`type(e).__name__`) not the message for vault/crypto exceptions.
2. **No plaintext secrets on disk** — decrypted vault data is processed in memory only. No `tempfile` writes of decrypted content.
3. **No secrets in error messages** — `VaultError` messages raised to the user must not contain decrypted data or passwords.
4. **File permissions enforced** — vault files must be validated at 600 (`-rw-------`) via `JSONValidator.validate_file_permissions()` before reading. New code paths that read vault files must call this.
5. **Password sourcing** — vault password comes from `VAULT_PASSWORD` env var or interactive `getpass.getpass()`. Never accept it as a CLI positional/flag argument (it would appear in process lists).
6. **Input validation at boundaries** — validate JSON structure with `JSONValidator.validate_json_structure()` on all user-supplied input files before processing.

## OWASP areas most relevant to this codebase
- **Injection**: Shell commands are run via `subprocess`; always use list form (`subprocess.run([...])`) never `shell=True` with user-controlled data.
- **Cryptographic failures**: Vault password must be passed as bytes to `VaultSecret`. Do not downgrade or bypass Ansible Vault's AES-256 encryption.
- **Security misconfiguration**: New files written by the tool should have permissions set to 600 immediately after creation (see `save_vault_file`).
- **Sensitive data exposure**: `json.dumps()` output of decrypted data must never be printed to stdout in non-read contexts.

## What to flag in code review
- Any `subprocess.run(..., shell=True)` with variables
- Any `logger.info/warning/error` that could interpolate a password or decrypted value
- Any `tempfile` usage that writes decrypted data
- Any new CLI argument that accepts a password value directly
- Any file write that omits a `chmod(0o600)` call
- `except Exception as e: ... raise VaultError(f"... {e}")` patterns that could leak vault content in the exception message — prefer `raise VaultError(f"... {type(e).__name__}")`
