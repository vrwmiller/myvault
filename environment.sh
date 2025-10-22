#!/bin/bash
# MyVault Development Environment Setup
# Usage: source environment.sh

# Note: Removed 'set -e' because it would exit the terminal when sourced
# Instead, we'll use explicit error checking for critical operations

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

echo "Setting up MyVault development environment..."

# Check if virtual environment exists
if [ ! -d "$PROJECT_ROOT/venv" ]; then
    echo "Error: Virtual environment not found at $PROJECT_ROOT/venv"
    echo "Please create it first with: python3 -m venv venv"
    echo "Skipping environment activation..."
    return 0
fi

# Deactivate any existing virtual environment
if [ -n "$VIRTUAL_ENV" ]; then
    echo "Deactivating existing virtual environment: $VIRTUAL_ENV"
    deactivate 2>/dev/null || true
    # Force clear the VIRTUAL_ENV variable
    unset VIRTUAL_ENV
fi

# Activate the project virtual environment
echo "Activating virtual environment: $PROJECT_ROOT/venv"
source "$PROJECT_ROOT/venv/bin/activate"

# Double-check and force set if needed
if [ "$VIRTUAL_ENV" != "$PROJECT_ROOT/venv" ]; then
    echo "Forcing virtual environment activation..."
    export VIRTUAL_ENV="$PROJECT_ROOT/venv"
    export PATH="$PROJECT_ROOT/venv/bin:$PATH"
fi

# Verify activation worked
if [ "$VIRTUAL_ENV" != "$PROJECT_ROOT/venv" ]; then
    echo "Error: Failed to activate virtual environment properly"
    echo "Expected: $PROJECT_ROOT/venv"
    echo "Got: $VIRTUAL_ENV"
    echo "Continuing anyway..."
else
    echo "Virtual environment activated successfully"
fi

# Update PATH to prioritize venv binaries
export PATH="$PROJECT_ROOT/venv/bin:$PATH"

# Set project-specific environment variables
export PYTHONPATH="$PROJECT_ROOT:$PYTHONPATH"
export MYVAULT_PROJECT_ROOT="$PROJECT_ROOT"

# Install/update dependencies
echo "Installing/updating Python dependencies..."
pip install -r requirements.txt

# Optional: Set default vault password environment variable
# export VAULT_PASSWORD="your_default_password_here"

echo "Environment setup complete!"
echo "Project root: $PROJECT_ROOT"
echo "Python: $(which python)"
echo "Pip: $(which pip)"
echo "Virtual environment: $VIRTUAL_ENV"

# Display available development commands
echo ""
echo "Available development commands:"
echo "  python3 myvault.py --help        # Run MyVault"
echo "  python3 run_tests.py             # Run test suite"
echo "  bandit -r myvault.py              # Security scan"
echo ""
echo "Dependencies are automatically installed/updated by this script."
echo "Pro tip: Add 'alias myvault=\"python3 \$MYVAULT_PROJECT_ROOT/myvault.py\"' to your shell"