# MyVault Workflow

This diagram illustrates the complete runtime workflow of `myvault.py`, from CLI invocation through each command handler.

```mermaid
flowchart TD
    START([Start: python myvault.py]) --> M1

    M1["Parse CLI args
    -f/--file, command, --debug"] --> M2{Command
    provided?}
    M2 -- No --> M3([Print help / Exit 1])
    M2 -- Yes --> M4["setup_logging
    file always, console if --debug"]
    M4 --> M5{VAULT_PASSWORD
    env var set?}
    M5 -- Yes --> M6[Use env var as
    vault password]
    M5 -- No --> M7["getpass.getpass
    Prompt interactively"]
    M7 --> M8{Input
    received?}
    M8 -- "Empty" --> MPWERR([Print: password cannot be empty / Exit 1])
    M8 -- "Ctrl-C" --> MCANCEL([Print: Operation cancelled by user / Exit 1])
    M8 -- "EOF" --> MEOFERR([Print: No password input received / Exit 1])
    M8 -- Yes --> M6
    M6 --> M10{Route
    command}

    M10 -- validate --> VSUB
    M10 -- read --> RSUB
    M10 -- create --> CSUB
    M10 -- update --> USUB
    M10 -- delete --> DSUB
    M10 -- edit --> ESUB

    VSUB & RSUB & CSUB & USUB & DSUB & ESUB --> MERR

    MERR{"VaultError or
    unexpected exception?"}
    MERR -- Yes --> MEXIT([Print to stderr / Exit 1])
    MERR -- No --> MEND([Exit 0])

    subgraph VSUB[validate]
        direction TB
        V1[Check input file exists] --> V2["validate_file_permissions
        no group/other bits allowed"]
        V2 --> V3[json.load file]
        V3 --> V4{JSON valid?}
        V4 -- No --> VERR([Raise VaultError])
        V4 -- Yes --> V5["validate_json_structure
        each entry must have 'property'"]
        V5 --> V6{Structure
        valid?}
        V6 -- No --> VERR
        V6 -- Yes --> V7["Check duplicate properties
        Report all fields used"]
        V7 --> V8([Print: JSON validation completed successfully!])
    end

    subgraph RSUB[read]
        direction TB
        R1[validate_file_permissions] --> R2["VaultManager
        decrypt vault file"]
        R2 --> R3{Vault empty?}
        R3 -- Yes --> RNONE([Print: no entries])
        R3 -- No --> R4{"--property
        filter set?"}
        R4 -- Yes --> R5["match_property_expression
        glob patterns + pipe alternatives"]
        R5 --> R6{Matches found?}
        R6 -- No --> RNONE
        R6 -- Yes --> R7[Filtered entries]
        R4 -- No --> R7
        R7 --> R8{"-o output file?"}
        R8 -- Yes --> R9(["Write JSON to file
        mode 600"])
        R8 -- No --> R10{"--format"}
        R10 -- "pipe (default)" --> R11(["Print: property | user
        | pass | ... per entry"])
        R10 -- json --> R12([Print: JSON array to stdout])
        R10 -- raw --> R13{"--field given?"}
        R13 -- No --> RERR([Raise VaultError])
        R13 -- Yes --> R14([Print raw field value per entry])
    end

    subgraph CSUB[create]
        direction TB
        C1["Check input file
        validate_file_permissions"] --> C2["json.load +
        validate_json_structure"]
        C2 --> C3["VaultManager
        load_vault_file"]
        C3 --> C4{Property
        conflicts?}
        C4 -- Yes --> C5["Prompt: continue
        anyway? y/N"]
        C5 -- No --> CCANCEL([Cancelled])
        C5 -- Yes --> C6["Merge: existing
        + new entries"]
        C4 -- No --> C6
        C6 --> C7["VaultManager
        save_vault_file mode 600"]
        C7 --> C8(["Print: created N entries
        total M in vault"])
    end

    subgraph USUB[update]
        direction TB
        U1["Check input file
        validate_file_permissions"] --> U2["json.load +
        validate_json_structure"]
        U2 --> U3["VaultManager
        load_vault_file"]
        U3 --> U4{Vault has
        entries?}
        U4 -- No --> UERR([Raise VaultError])
        U4 -- Yes --> U5[Build property index map]
        U5 --> U6["Merge update fields
        into matched entries"]
        U6 --> U7{Properties
        not found?}
        U7 -- Yes --> U8[Prompt: continue? y/N]
        U8 -- No --> UCANCEL([Cancelled])
        U8 -- Yes --> U9{Any entries
        updated?}
        U7 -- No --> U9
        U9 -- No --> U10([Print: no updates])
        U9 -- Yes --> U11["VaultManager
        save_vault_file mode 600"]
        U11 --> U12([Print: updated N entries])
    end

    subgraph DSUB[delete]
        direction TB
        D1["VaultManager
        load_vault_file"] --> D2{Vault has
        entries?}
        D2 -- No --> DNONE([Print: no entries])
        D2 -- Yes --> D3["match_property_expression
        find candidates"]
        D3 --> D4{Matches found?}
        D4 -- No --> DNONE2([Print: no matches])
        D4 -- Yes --> D5{"--force flag?"}
        D5 -- No --> D6["Display entries with
        sensitive fields masked"]
        D6 --> D7["Per-entry y/n/q
        confirmation loop"]
        D7 -- "q / quit" --> DCANCEL([Cancelled])
        D7 -- "All entries reviewed" --> D8["Final summary
        Proceed? y/N"]
        D8 -- No --> DCANCEL
        D8 -- Yes --> D9["Remove entries
        reverse index order"]
        D5 -- Yes --> D9
        D9 --> D10{Entries
        remaining?}
        D10 -- Yes --> D11["VaultManager
        save_vault_file mode 600"]
        D10 -- No --> D12["os.remove
        vault file"]
        D11 --> D13([Print: deleted N, M remaining])
        D12 --> D13
    end

    subgraph ESUB[edit]
        direction TB
        ED1["Resolve editor
        CLI arg > $EDITOR > vi"] --> ED2[validate_file_permissions]
        ED2 --> ED3["VaultManager
        load_vault_file"]
        ED3 --> ED4["_secure_tmpdir
        RAM disk (macOS) / tmpfs (Linux)
        or on-disk fallback with warning"]
        ED4 --> ED5["Write decrypted JSON
        to tmp file mode 600"]
        ED5 --> ED6["subprocess.call
        open editor on tmp file"]
        ED6 --> ED7{"Exit code == 0?"}
        ED7 -- No --> ED8([Abort: no changes saved])
        ED7 -- Yes --> ED9["Read edited file
        json.loads + validate_json_structure"]
        ED9 --> ED10{Valid JSON
        and structure?}
        ED10 -- No --> ED11["Prompt: re-open
        editor? y/N"]
        ED11 -- Yes --> ED6
        ED11 -- No --> ED12([Cancelled])
        ED10 -- Yes --> ED13["VaultManager
        save_vault_file mode 600"]
        ED13 --> ED14([Print: vault saved N entries])
        ED8 & ED12 & ED14 --> EDCLEAN["Zero-fill then
        delete temp file"]
    end
```

## Component overview

| Component | Role |
|---|---|
| `main()` | Entry point: parses args, loads password, routes to command handlers |
| `setup_logging()` | Configures file logging always; adds console handler only in `--debug` mode |
| `JSONValidator` | Validates vault file permissions (owner-only access: no group/other bits) and JSON structure (required `property` field) |
| `VaultManager` | Wraps Ansible `VaultLib` to encrypt/decrypt vault files using the provided password |
| `match_property_expression()` | Evaluates glob patterns and pipe-separated alternatives against a property value |
| `_secure_tmpdir()` | Context manager that provides a memory-backed (RAM disk / tmpfs) temp directory for edit operations |
| `handle_validate()` | Validates a plaintext JSON file structure without touching the vault |
| `handle_read()` | Decrypts the vault and outputs matching entries in pipe, JSON, or raw format |
| `handle_create()` | Merges new entries from a JSON file into the encrypted vault |
| `handle_update()` | Merges field-level updates from a JSON file into existing vault entries |
| `handle_delete()` | Removes matching entries from the vault with per-entry confirmation (or `--force`) |
| `handle_edit()` | Decrypts the vault to a secure temp file, opens an editor, validates, and re-encrypts on save |
