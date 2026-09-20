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
import sqlite3
import sys

# Craft the malicious input
malicious_input = 'admin'; name: 'admin'; password: 'password'

# Connect to the SQLite database
conn = sqlite3.connect(':memory:')

# Execute the malicious query
result = conn.execute("SELECT * FROM u WHERE n = '%s'" % malicious_input).fetchall()

# Print the result
print(result)

# Check if the bug was triggered
if result:
    print('VULN_CONFIRMED_SQLI')
else:
    print('No SQL injection vulnerability found')
