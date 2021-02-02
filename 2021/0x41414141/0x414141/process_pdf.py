#!/usr/bin/env python3

corrupted = open('smashing.pdf', 'rb')
data = corrupted.read()

new_file = open('unsmashed.pdf', 'wb')

new_file.write((''.join(chr(i ^ 0x41) for i in data)).encode('charmap'))
