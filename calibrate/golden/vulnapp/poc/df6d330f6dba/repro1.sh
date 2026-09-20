#!/bin/bash
# Exploit the RCE vulnerability in app.js:5
# Send a request with a malicious expression in the 'expr' query parameter
# Example request: http://x/?expr=alert('VULN_CONFIRMED_RCE')
# The script will print 'VULN_CONFIRMED_RCE' if the bug is exploited
# Note: This is a non-destructive PoC and should not be used for malicious purposes
# Fix: Ensure the script runs in a network-less Docker sandbox with the repo mounted read-only at /src
# Example fix: python3 - <<'PY' ... PY
# or write a file under /poc then run it
# PYTHONPATH=/src/lib3 python3 /poc/r.py
# Note: This is a non-destructive PoC and should not be used for malicious purposes