---
applyTo: "tests/**"
---

# Test Agent Instructions

## Project context
- Main source: `myvault.py` — a single-file Python CLI tool. All classes (`VaultManager`, `JSONValidator`) and helpers (`match_property_expression`) are defined there.
- Test framework: pytest with `tests/conftest.py` for shared fixtures, `tests/test_myvault.py` for all test cases.
- Vault operations (Ansible Vault encrypt/decrypt) **must always be mocked** in unit tests — never perform real encryption in tests.

## Fixtures available in conftest.py
- `sample_vault_entries` — list of 5 vault entry dicts matching the JSON schema
- `sample_vault_entry` — a single vault entry dict
- `mock_vault_components` — mocked `VaultSecret` and `VaultLib` instances
- `temp_vault_file` — a temporary file with mock encrypted bytes, permissions set to 600
- `temp_json_input_file` — a temporary JSON file written with `sample_vault_entries`, permissions 600

## JSON vault schema
Every entry is a dict with a required `property` field plus arbitrary string fields:
```json
{"property": "website1.com", "username": "user", "password": "secret", "notes": "..."}
```

## Test writing conventions
- Class per logical unit: `TestPropertyExpressions`, `TestJSONValidator`, `TestVaultManager`, `TestCommandHandlers`
- Name tests `test_<action>_<condition>` (e.g., `test_decrypt_data_json_error`)
- Use `pytest.raises(VaultError, match="...")` for all error path assertions
- Patch at the module level: `@patch('myvault.VaultLib')`, not at the import level
- Use `capsys.readouterr()` to assert CLI output; never assert on log file content
- Do not assert on log messages — logs go to `myvault.log`, not stdout/stderr by default

## Running tests
```bash
source venv/bin/activate
python -m pytest tests/ -v --tb=short
python -m pytest tests/ --cov=myvault --cov-report=term-missing
```

## Coverage expectations
- All public methods of `VaultManager` and `JSONValidator` must have tests
- Happy path + at least one error path per method
- `match_property_expression`: glob, pipe-separated, case-insensitive, and empty-input cases
