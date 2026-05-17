#!/bin/bash
# MyVault Development Environment Setup
# Usage: source environment.sh

# Note: Removed 'set -e' because it would exit the terminal when sourced
# Instead, we'll use explicit error checking for critical operations

# Get the directory where this script is located
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$SCRIPT_DIR"

echo "Setting up MyVault development environment..."

# Minimum Python version required (update only when project requirements change)
MIN_PYTHON_VERSION="3.12"

# Find the newest installed Python that meets the minimum version requirement.
# Scans python3.X (X = 30..MIN_MINOR) so new releases are picked up automatically.
find_suitable_python() {
    local min_major min_minor
    min_major=$(echo "$MIN_PYTHON_VERSION" | cut -d. -f1)
    min_minor=$(echo "$MIN_PYTHON_VERSION" | cut -d. -f2)

    for minor in $(seq 30 -1 "$min_minor"); do
        local candidate="${min_major}.${minor}"
        if command -v "python${candidate}" &>/dev/null; then
            echo "python${candidate}"
            return 0
        fi
    done

    # Fall back to generic python3 if it satisfies the minimum
    if command -v python3 &>/dev/null && \
       python3 -c "import sys; sys.exit(0 if sys.version_info >= ($min_major, $min_minor) else 1)" 2>/dev/null; then
        echo "python3"
        return 0
    fi

    echo "Error: Python >= $MIN_PYTHON_VERSION not found. Install Python >= $MIN_PYTHON_VERSION and ensure it is available on PATH." >&2
    return 1
}

# Check if virtual environment exists, creating it with the best available Python
if [ ! -d "$PROJECT_ROOT/venv" ]; then
    PYTHON_BIN="$(find_suitable_python)" || return 1
    "$PYTHON_BIN" -m venv "$PROJECT_ROOT/venv" || return 1
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
python3 -m pip install --upgrade pip
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

# Set up myvault alias for convenient usage
alias myvault="python3 $MYVAULT_PROJECT_ROOT/myvault.py"
echo "Alias 'myvault' created for convenient usage (active in this session)"
