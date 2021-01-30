#!/usr/bin/env python3

from pwn import *
from bubble_sort import perform_bubble_sort
from re import *

io = remote('45.134.3.200', 9660)

print(io.recvline())
print(io.recvline())
level = 1

def solution(level, elements):
    if level == 1:
        return pow(2, len(elements)) - 1
    if level == 2:
        return perform_bubble_sort(elements)
    return 0  
def parse_challenge(challenge):
    result = re.search("\[(.*)\]", challenge).group(1)
    result = result.split(', ')
    result = list(map(lambda x : int(x), result))
    return result

while True:
    challenge = io.recvlineS()
    print(challenge)
    if 'level' in challenge:
        level += 1
        challenge = io.recvlineS()
        print(challenge)

    elements = parse_challenge(challenge)
    answer = solution(level, elements)
    print("Answer:", answer)

    io.sendline(str(answer))

    prompt = io.recvuntilS('>')
    print(prompt)

# flag{g077a_0pt1m1ze_3m_@ll}
