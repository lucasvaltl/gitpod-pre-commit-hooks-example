#!/usr/bin/env python3
"""
Password detector for pre-commit hooks.
Detects passwords that are exactly 14 characters, start with P/p,
and contain at least one uppercase, lowercase, digit, and special character.
"""

import argparse
import re
import sys
from pathlib import Path


def is_binary_file(file_path):
    """Check if file is binary by reading first 1024 bytes."""
    try:
        with open(file_path, 'rb') as f:
            chunk = f.read(1024)
            return b'\0' in chunk
    except Exception:
        return True


def detect_passwords_in_file(file_path):
    """
    Detect passwords matching the specific pattern in a file.
    Returns list of (line_number, line_content, password) tuples.
    """
    violations = []

    if is_binary_file(file_path):
        return violations

    # Character class for valid password characters
    char_class = r'[A-Za-z0-9!@#$%^&*()_+\-=\[\]{}|;:,.<>?]'

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                # Find all 14-char sequences starting with P/p
                potential_matches = re.finditer(rf'[Pp]{char_class}{{13}}', line)

                for match in potential_matches:
                    password = match.group(0)

                    # Check if it has all required character types
                    has_upper = bool(re.search(r'[A-Z]', password))
                    has_lower = bool(re.search(r'[a-z]', password))
                    has_digit = bool(re.search(r'[0-9]', password))
                    has_special = bool(re.search(r'[!@#$%^&*()_+\-=\[\]{}|;:,.<>?]', password))

                    if has_upper and has_lower and has_digit and has_special:
                        violations.append((line_num, line.strip(), password))
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)

    return violations

    violations = []

    if is_binary_file(file_path):
        return violations

    try:
        with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
            for line_num, line in enumerate(f, 1):
                matches = password_pattern.finditer(line)
                for match in matches:
                    password = match.group(0)
                    violations.append((line_num, line.strip(), password))
    except Exception as e:
        print(f"Warning: Could not read {file_path}: {e}", file=sys.stderr)

    return violations


def mask_password(password):
    """Mask password showing only first 2 and last 2 characters."""
    if len(password) <= 4:
        return '*' * len(password)
    return password[:2] + '*' * (len(password) - 4) + password[-2:]


def main():
    parser = argparse.ArgumentParser(description='Detect specific password patterns in files')
    parser.add_argument('files', nargs='*', help='Files to scan')
    parser.add_argument('--verbose', '-v', action='store_true', help='Verbose output')

    args = parser.parse_args()

    if not args.files:
        print("No files provided to scan")
        return 0

    total_violations = 0

    for file_path in args.files:
        path = Path(file_path)
        if not path.exists():
            if args.verbose:
                print(f"Skipping non-existent file: {file_path}")
            continue

        if not path.is_file():
            if args.verbose:
                print(f"Skipping non-file: {file_path}")
            continue

        violations = detect_passwords_in_file(file_path)

        if violations:
            total_violations += len(violations)
            print(f"\n🚨 PASSWORD DETECTED in {file_path}:")
            for line_num, line_content, password in violations:
                masked = mask_password(password)
                print(f"  Line {line_num}: {masked}")
                if args.verbose:
                    print(f"    Full line: {line_content}")

            print(f"\n📋 REMEDIATION REQUIRED:")
            print(f"  - Remove or replace the detected password(s) in {file_path}")
            print(f"  - Use environment variables or secure secret management")
            print(f"  - Never commit passwords to version control")
        elif args.verbose:
            print(f"✅ No password violations found in {file_path}")

    if total_violations > 0:
        print(f"\n❌ COMMIT BLOCKED: Found {total_violations} password violation(s)")
        print("Fix the issues above before committing.")
        return 1
    else:
        if args.verbose:
            print(f"\n✅ All {len(args.files)} files passed password detection")
        return 0


if __name__ == '__main__':
    sys.exit(main())
