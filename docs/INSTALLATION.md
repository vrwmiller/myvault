# Installation Guide

## Prerequisites

- Python 3.6 or higher
- `venv` module (included with Python 3.3+)

## Quick Setup (Recommended)

For the fastest setup experience, use the provided environment script:

1. Clone the repository:

   ```bash
   git clone https://github.com/vrwmiller/myvault.git
   cd myvault
   ```

2. Create virtual environment:

   ```bash
   python3 -m venv venv
   ```

3. Set up development environment:

   ```bash
   source environment.sh
   ```

The environment script will automatically:
- Activate the virtual environment
- Install/update all dependencies from `requirements.txt`
- Set up project environment variables
- Optionally prompt for vault password setup
- Provide helpful development commands
- Handle environment conflicts gracefully

## Manual Setup (Alternative)

If you prefer manual control over the setup process:

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

## Virtual Environment Management

### Using the Environment Script (Recommended)

After initial setup, simply use the environment script each time you want to work on the project:

```bash
# Navigate to project directory
cd myvault

# Activate environment and show available commands
source environment.sh

# Use the tool
python3 myvault.py -f your_vault_file.json read

# Deactivate when done (optional)
deactivate
```

The environment script provides helpful commands and handles activation robustly.

### Manual Environment Management

Alternatively, you can manage the virtual environment manually:

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

## Vault Password Setup

The environment script can optionally prompt you to set up a vault password for the session:

- **Interactive setup**: The script will ask if you want to set a vault password
- **Secure input**: Password entry is hidden during typing
- **Session-based**: Password persists only for the current terminal session
- **Optional**: You can skip this and set the password later or be prompted when needed

For permanent vault password setup, add to your shell profile:
```bash
export VAULT_PASSWORD="your_vault_password"
```