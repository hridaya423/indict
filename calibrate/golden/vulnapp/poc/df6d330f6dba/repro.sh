#!/bin/bash
# Exploit the RCE vulnerability in app.js:5
# Send a request with a malicious expression in the 'expr' query parameter
# Example request: http://x/?expr=alert('VULN_CONFIRMED_RCE')
# The script will print 'VULN_CONFIRMED_RCE' if the bug is exploited
# Note: This is a non-destructive PoC and should not be used for malicious purposes