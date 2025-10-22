# Development Guide

## Development Commands

When using the environment script, you'll see available development commands:

```bash
# Security scanning
bandit -r myvault.py              # Static code security analysis

# Testing
python3 run_tests.py             # Run test suite with coverage

# Application usage
python3 myvault.py --help        # Show application help
```

These commands are automatically available after running `source environment.sh`.
Dependencies are installed automatically by the environment script.

## Running Tests

```bash
# Activate virtual environment
source venv/bin/activate

# Run all tests
python3 run_tests.py

# Run specific test modules
python3 -m pytest tests/test_myvault.py -v

# Run with coverage
python3 -m pytest tests/ --cov=myvault --cov-report=html
```

## Test Structure

- `tests/test_myvault.py` - Main test suite with unit and integration tests
- `run_tests.py` - Test runner with coverage reporting
- All vault operations are mocked for security and deterministic results

## Security Considerations

### Code Security

- **Static analysis**: Bandit scans for common security vulnerabilities
- **No hardcoded secrets**: All sensitive data comes from environment variables or user input
- **Input validation**: JSON structure and file permissions are validated
- **Memory-only processing**: Decrypted data never written to temporary files
- **Comprehensive logging**: All operations logged with sensitive data redacted

### Testing Security

- **Mocked vault operations**: Tests never use real encrypted data
- **Deterministic results**: All random elements are controlled in tests
- **Isolated test environment**: Tests run in separate virtual environment
- **No persistent test data**: Test files are cleaned up after execution

## Project Structure

```
myvault/
├── myvault.py          # Main application script
├── environment.sh      # Development environment setup
├── requirements.txt    # Python dependencies
├── run_tests.py       # Test runner
├── tests/             # Test suite
│   └── test_myvault.py
├── examples/          # Example files and usage
├── docs/              # Documentation
│   ├── INSTALLATION.md
│   ├── EXAMPLES.md
│   ├── DEVELOPMENT.md
│   └── API.md
├── .github/           # GitHub configuration
│   ├── dependabot.yml
│   └── copilot-instructions.md
└── htmlcov/           # Test coverage reports
```

## Development Workflow

### Setting Up for Development

1. **Clone and setup**:
   ```bash
   git clone https://github.com/vrwmiller/myvault.git
   cd myvault
   python3 -m venv venv
   source environment.sh
   ```

2. **Verify setup**:
   ```bash
   python3 myvault.py --help
   bandit -r myvault.py
   python3 run_tests.py
   ```

### Making Changes

1. **Create feature branch**:
   ```bash
   git checkout -b feature/your-feature-name
   ```

2. **Make changes and test**:
   ```bash
   # Edit code
   bandit -r myvault.py              # Security scan
   python3 run_tests.py             # Run tests
   python3 myvault.py --help        # Verify functionality
   ```

3. **Commit and push**:
   ```bash
   git add .
   git commit -m "Description of changes"
   git push origin feature/your-feature-name
   ```

### Code Quality Standards

- **Security first**: Use bandit to scan for vulnerabilities
- **Test coverage**: Maintain high test coverage (>90%)
- **Documentation**: Update relevant docs for user-facing changes
- **Error handling**: Comprehensive error handling with user-friendly messages
- **Logging**: Proper logging with sensitive data masking

## Automated Security

### GitHub Dependabot

The project uses GitHub Dependabot for automated security updates:

- **Weekly scans**: Checks for vulnerable dependencies every Monday
- **Automatic PRs**: Creates pull requests for security updates
- **Grouped updates**: Dependencies are grouped to reduce PR noise
- **Configuration**: See `.github/dependabot.yml` for settings

### Security Scanning

- **Bandit**: Static code analysis for Python security issues
- **Dependency scanning**: Automated via GitHub Dependabot
- **Code reviews**: Manual security review for all changes

## Contributing

### Guidelines

1. **Fork the repository**
2. **Create a feature branch** from `main`
3. **Make your changes** with appropriate tests
4. **Ensure all tests pass** and security scans are clean
5. **Update documentation** if needed
6. **Submit a pull request** with clear description

### Pull Request Requirements

- ✅ All tests pass
- ✅ Security scan (bandit) shows no issues  
- ✅ Code follows existing style and patterns
- ✅ Documentation updated for user-facing changes
- ✅ Commit messages are clear and descriptive

### Code Review Process

1. **Automated checks**: Tests and security scans must pass
2. **Manual review**: Code quality and security review
3. **Documentation check**: Ensure docs are updated
4. **Merge approval**: Requires maintainer approval

## Release Process

1. **Version update**: Update version numbers if applicable
2. **Test suite**: Ensure all tests pass on multiple Python versions
3. **Security scan**: Clean bandit scan required
4. **Documentation**: Update changelogs and docs
5. **Tag release**: Create git tag with version number
6. **GitHub release**: Create release with changelog

## Troubleshooting Development Issues

### Common Issues

**Virtual environment problems**:
```bash
# Reset virtual environment
rm -rf venv
python3 -m venv venv
source environment.sh
```

**Permission errors**:
```bash
# Fix script permissions
chmod +x myvault.py run_tests.py environment.sh
```

**Import errors**:
```bash
# Verify Python path
echo $PYTHONPATH
# Should include project root
```

### Debug Mode

Enable debug logging for development:
```bash
python3 myvault.py -d -f test_vault.json read
```

### Testing with Real Vaults

**⚠️ Never use production vaults in development!**

Create test vaults:
```bash
# Create test vault with sample data
python3 myvault.py validate -i examples/sample_vault.json
python3 myvault.py -f test_vault.json create -i examples/sample_vault.json
```