#!/usr/bin/env python3
"""
Test runner script for myvault tests.

This script runs the test suite and generates coverage reports.
"""

import subprocess
import sys
import os

def run_tests():
    """Run the test suite with coverage."""
    print("🧪 Running myvault test suite...")
    print("=" * 50)
    
    # Basic test run
    result = subprocess.run([
        sys.executable, "-m", "pytest", 
        "tests/", 
        "-v", 
        "--tb=short"
    ], cwd=os.path.dirname(__file__))
    
    if result.returncode == 0:
        print("\n✅ All tests passed!")
        
        # Run with coverage if available
        print("\n📊 Running coverage analysis...")
        coverage_result = subprocess.run([
            sys.executable, "-m", "pytest",
            "tests/",
            "--cov=myvault",
            "--cov-report=term-missing",
            "--cov-report=html"
        ], cwd=os.path.dirname(__file__))
        
        if coverage_result.returncode == 0:
            print("\n📋 Coverage report generated in htmlcov/")
        
    else:
        print("\n❌ Some tests failed!")
        sys.exit(1)

if __name__ == "__main__":
    run_tests()