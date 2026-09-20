#!/bin/bash
# Craft a malicious input to trigger the SQL injection vulnerability
# Example: attacker input -> get_user() -> sqlite3.connect() -> conn.execute() -> fetchall()
# Use the 'name' parameter to execute arbitrary SQL commands
# Example: attacker input: 'admin'; name: 'admin'; password: 'password'
# The script will print 'VULN_CONFIRMED_SQLI' if the bug fires
# Note: This is a non-destructive reproduction and should not be weaponized
# Example usage:
# ./reproduce_sqli.sh

# Import necessary libraries
PYTHONPATH=/src/lib3 python3 - <<'PY' ... PY
