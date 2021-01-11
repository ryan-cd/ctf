#!/usr/bin/env python3

import sys
import hashlib
import base64

salt = 'mrgrinch463'
target = sys.argv[1]
auth = hashlib.md5((salt + target).encode('utf-8')).hexdigest()
payload = f"{{\"target\":\"{target}\",\"hash\":\"{auth}\"}}"
print("Preparing", payload)
print(base64.b64encode(payload.encode('utf-8')).decode())
