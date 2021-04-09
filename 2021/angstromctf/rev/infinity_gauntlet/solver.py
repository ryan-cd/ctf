#!/usr/bin/env python3

import itertools
import re
from pwn import *
from foobar import foo, bar

MAX_FLAG_LENGTH = 264

binary = context.binary = ELF('./infinity_gauntlet')
if args.REMOTE:
    io = remote('shell.actf.co', 21700)
else:
    io = process(binary.path)

flag = [set() for x in range(MAX_FLAG_LENGTH)]    

# Print welcome message
for i in range(2):
    log.info(io.recvline())

# whichever of x or y is present is the (random_int%1337)
def set_flag_char(i, x, y, result):
    print(i, x, y, result)
    if x is None:
        contains_flag_byte = result ^ (y % 1337 + 1) ^ 1337
    elif y is None:
        contains_flag_byte = result ^ (x % 1337) ^ 1337 - 1

    encoded_char = contains_flag_byte & 0xff

    for j in range(MAX_FLAG_LENGTH):
        if contains_flag_byte == (j % MAX_FLAG_LENGTH + i & 0xff) << 8 | encoded_char:
            item = chr(encoded_char ^ (0x11*j)%256)
            if item in '1234567890qwertyuiopasdfghjklzxcvbnm_\{\}':
                flag[j].add(item)

def display_flag_candidate():
    flag_length = flag.index(set())
    flag = flag[:flag_length]
    for permutation in itertools.product(*flag):
        flag_candidate = ''.join(list(permutation))
        if re.match('actf\{[a-zA-Z0-9_]+\}', flag_candidate):
            print(flag_candidate)

    # actf{snapped_away_the_end}                

for i in range(1, 600):
    log.info(io.recvline())
    challenge = io.recvlineS()
    log.info(challenge)
    if 'foo' in challenge:
        match = re.search('foo\((\?|\d+), (\?|\d+)\) = (\?|\d+)', challenge)
        args = [None if a == '?' else int(a) for a in match.groups()]

        # Iterations 50 and up contain flag information
        if i >= 50:
            if match.groups().index('?') == 1:
                set_flag_char(i, args[0], args[1], args[2]) # x is random_int
            elif match.groups().index('?') == 0:
                set_flag_char(i, args[0], args[1], args[2]) # y is random_int
            else:
                # skip this case for now, don't want to do the extra math
                pass    
        io.sendline(str(foo(*args)))
    elif 'bar' in challenge:
        match = re.search('bar\((\?|\d+), (\?|\d+), (\?|\d+)\) = (\?|\d+)', challenge)
        args = [None if a == '?' else int(a) for a in match.groups()]
        io.sendline(str(bar(*args)))
    log.info(io.recvline())

io.close()

display_flag_candidate()
