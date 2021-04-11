# Pastebin
**Category: Reverse Engineering**


## Completing Registration

After registering for the CTF, I was redirected to [this pastebin link](https://pastebin.com/raw/5QjXp98s).

The page had a brief registration confirmation message in French, and then a ton of random characters on it:
```
Votre inscription est validée !

Voici un premier challenge pour vous donner un avant goût du CTF, vous avez 30 challenges disponibles sur le twitter @CTF_Inter_IUT pour vous entraîner.

f0VMRgIBAQAAAAAAAAAAAAMAPgABAAAAgBAAAAAAAABAAAAAAAAAAGg6AAAAAAAAAAAAAEAAOAALAEAAHgAdAAYAAAAEAAAAQAAAAAAAAABAAAAAAAAAAEAAAAAAAAAAaAIAAAAAAABoAgAAAAAAAAgAAAAAAAAAAwAAAAQAAACoAgAAAAAAAKgCAAAAAAAAqAIAAAAAAAAcAAAAAAAAABwAAAAAAAAAAQAAAAAAAAABAAAABAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAEgGAAAAAAAASAYAAAAAAAAAEAAAAAAAAAEAAAAFAAAAABAAAAAAAAAAEAAAAAAAAAAQAAAAAAAAjQMAAAAAAACNAwAAAAAAAAAQAAAAAAAAAQAAAAQAAAAAIAAAAAAAAAAgAAAAAAAAACAAAAAAAADQAgAAAAAAANACAAAAAAAAABAAAAAAAAABAAAABgAAAOgtAAAAAAAA6D0AAAAAAADoPQAAAAAAAGACAAAAAAAAeAIAAAAAAAAAEAAAAAAAAAIAAAAGAAAA+C0AAAAAAAD4PQAAAAAAAPg9AAAAAAAA4AEAAAAAAADgAQAAAAAAAAgAAAAAAAAABAAAAAQAAADEAgAAAAAAAMQCAAAAAAAAxAIAAAAAAABEAAAAAAAAAEQAAAAAAAAABAAAAAAAAABQ5XRkBAAAAHwhAAAAAAAAfCEAAAAAAAB8IQAAAAAAADwAAAAAAAAAPAAAAAAAAAAEAAAAAAAAAFHldGQGAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABAAAAAAAAAAUuV0ZAQAAADoLQA...<snipped>
```

Seeing the French made me think I'd better grind some Duolingo before getting into the real challenges. Seeing the random character string made me think there was some encoded data being obscured.

The characters used seemed to suggest base64 encoding. Converting that into ascii resulted in the following:

![conversion](images/conversion.png)

The output includes 'ELF' (Executable and Linkable Foramt) at the top, suggesting that this is a linux binary. Let's save this file and see what it does.

## Seeing What It Does
Let's pop this into Ghidra and decompile the binary.

```c
undefined8 main(undefined4 param_1,undefined8 param_2)

{
  char *pcVar1;
  size_t sVar2;
  undefined8 uVar3;
  char acStack152 [40];
  undefined8 uStack112;
  undefined8 local_68;
  undefined4 local_5c;
  int local_54;
  char *local_50;
  undefined8 local_48;
  int local_40;
  int local_3c;
  
  uStack112 = 0x101194;
  local_68 = param_2;
  local_5c = param_1;
  printf("Please enter the flag > ");
  local_48 = 0x25;
  local_50 = acStack152;
  pcVar1 = fgets(acStack152,0x26,stdin);
  if (pcVar1 == (char *)0x0) {
    puts("C\'est non !");
    uVar3 = 1;
  }
  else {
    sVar2 = strlen(local_50);
    local_54 = (int)sVar2;
    if (local_54 == 0x25) {
      local_40 = 0;
      while (local_40 < 0x25) {
        local_50[local_40] = local_50[local_40] + 0x18U ^ 0x2a;
        local_40 = local_40 + 1;
      }
      local_3c = 0;
      while (local_3c < 0x25) {
        if ((int)local_50[local_3c] != *(int *)(FLAG + (long)local_3c * 4)) {
          puts("https://tinyurl.com/snyyqw7 !");
          return 1;
        }
        local_3c = local_3c + 1;
      }
      puts(
          "Bien joué !\nEnvoyez nous le flag en MP sur Twitter @CTF_Inter_IUT pour prouver votre talent"
          );
      uVar3 = 0;
    }
    else {
      puts("C\'est non !");
      uVar3 = 1;
    }
  }
  return uVar3;
}
```

Let's break this down piece by piece.

```c
  printf("Please enter the flag > ");
  local_48 = 0x25;
  local_50 = acStack152;
  pcVar1 = fgets(acStack152,0x26,stdin);
  if (pcVar1 == (char *)0x0) {
    puts("C\'est non !");
    uVar3 = 1;
  }
```
The program prompts us to enter the flag. It then reads in `0x26` (which equals 37) characters of input. If we wrote less than 37 characters, we get the message "C'est non !", indicating we entered the wrong value.

Continuing to the next section:
```c
  else {
    sVar2 = strlen(local_50);
    local_54 = (int)sVar2;
    if (local_54 == 0x25) {
    //...<snipped>
    }
    else {
      puts("C\'est non !");
      uVar3 = 1;
    }
  }
```

Recall that `local_50` contains our input. This is checking that the input length is `0x25` (which equals 37). If the length is correct, the program continues to the main part of the algorithm. Otherwise, it prints another fail message.

Onto the first part of the section that was snipped:

```c
      local_40 = 0;
      while (local_40 < 0x25) {
        local_50[local_40] = local_50[local_40] + 0x18U ^ 0x2a;
        local_40 = local_40 + 1;
      }
```

This is applying some transformations to our input. We iterate once for every position in our input string. Each byte of the input is first added by `0x18` and then has an `xor` applied with `0x2a`. 

Finally:

```c
      local_3c = 0;
      while (local_3c < 0x25) {
        if ((int)local_50[local_3c] != *(int *)(FLAG + (long)local_3c * 4)) {
          puts("https://tinyurl.com/snyyqw7 !");
          return 1;
        }
        local_3c = local_3c + 1;
      }
      puts(
          "Bien joué !\nEnvoyez nous le flag en MP sur Twitter @CTF_Inter_IUT pour prouver votre talent"
          );
```
One more loop to iterate from 0 to the length of the input. Don't forget that the input has been modified from what we originally put in by the while loop above. The `if` statement checks that this transformed input at each teration is equal to `FLAG + iterator * 4`. If it isn't, we get directed to this cheeky URL https://tinyurl.com/snyyqw7, and the program returns a failure. If the check passes, we get the success message, and we will know our input was right.

Explained a little more, `FLAG` is a label in the program. And we are checking that every element of the transformed input is equal to every fourth byte in the memory starting from label `FLAG`.

I used GDB to debug and see what bytes were in the memory following the `FLAG` label.

```c
(gdb) x/148b &FLAG
0x555555556040 <FLAG>:         0x77    0x00    0x00    0x00    0x4c    0x00    0x00    0x00
0x555555556048 <FLAG+8>:       0x41    0x00    0x00    0x00    0x4b    0x00    0x00    0x00
0x555555556050 <FLAG+16>:      0x70    0x00    0x00    0x00    0x41    0x00    0x00    0x00
0x555555556058 <FLAG+24>:      0xb9    0xff    0xff    0xff    0x63    0x00    0x00    0x00
0x555555556060 <FLAG+32>:      0xa1    0xff    0xff    0xff    0xa6    0xff    0xff    0xff
0x555555556068 <FLAG+40>:      0x5d    0x00    0x00    0x00    0xbb    0xff    0xff    0xff
0x555555556070 <FLAG+48>:      0x62    0x00    0x00    0x00    0xa7    0xff    0xff    0xff
0x555555556078 <FLAG+56>:      0x5d    0x00    0x00    0x00    0xa1    0xff    0xff    0xff
0x555555556080 <FLAG+64>:      0xaa    0xff    0xff    0xff    0x66    0x00    0x00    0x00
0x555555556088 <FLAG+72>:      0xae    0xff    0xff    0xff    0x63    0x00    0x00    0x00
0x555555556090 <FLAG+80>:      0x5d    0x00    0x00    0x00    0xac    0xff    0xff    0xff
0x555555556098 <FLAG+88>:      0x62    0x00    0x00    0x00    0xa6    0xff    0xff    0xff
0x5555555560a0 <FLAG+96>:      0x5d    0x00    0x00    0x00    0x67    0x00    0x00    0x00
0x5555555560a8 <FLAG+104>:     0xaa    0xff    0xff    0xff    0x53    0x00    0x00    0x00
0x5555555560b0 <FLAG+112>:     0xa0    0xff    0xff    0xff    0x61    0x00    0x00    0x00
0x5555555560b8 <FLAG+120>:     0x5d    0x00    0x00    0x00    0x54    0x00    0x00    0x00
0x5555555560c0 <FLAG+128>:     0xae    0xff    0xff    0xff    0x66    0x00    0x00    0x00
0x5555555560c8 <FLAG+136>:     0x55    0x00    0x00    0x00    0x67    0x00    0x00    0x00
0x5555555560d0 <FLAG+144>:     0xbf    0xff    0xff    0xff
```

Looking at every 4th byte, we get:
>  `0x77` (w), `0x4c` (L), `0x41` (A), `0x4b` (K)...

It became clear pretty quickly that this wasn't spelling anything. But then again, it doesn't really need to. Our input is the flag, and then it gets transformed before being compared with these values. By this point, we know enough to be able to calculate what the flag needs to be.

## Calculating What The Flag Needs To Be

For each of the bytes we care about, we will need to apply the calculation in reverse.

The per character calculation looks like this (where `x` is the original character and `FLAG_ENTRY` is the corresponding byte in the `FLAG` array that it needs to be transformed to):
```c
FLAG_ENTRY = (x + 0x18) ^ 0x2a
```

From here, we need to solve for x to find what the original character should be.

```c
FLAG_ENTRY = (x + 0x18) ^ 0x2a
(x + 0x18) ^ 0x2a = FLAG_ENTRY
(x + 0x18) ^ 0x2a ^ 0x2a = FLAG_ENTRY ^ 0x2a
(x + 0x18) ^ 0 = FLAG_ENTRY ^ 0x2a
x + 0x18 = (FLAG_ENTRY ^ 0x2a)
x = (FLAG_ENTRY ^ 0x2a) - 0x18
```

I put together a Python script to apply this formula to the `FLAG` bytes to calculate the input:

```python
FLAG_BYTES = [0x77,0x00,0x00,0x00,0x4c,0x00,0x00,0x00,
0x41,0x00,0x00,0x00,0x4b,0x00,0x00,0x00,
0x70,0x00,0x00,0x00,0x41,0x00,0x00,0x00,
0xb9,0xff,0xff,0xff,0x63,0x00,0x00,0x00,
0xa1,0xff,0xff,0xff,0xa6,0xff,0xff,0xff,
0x5d,0x00,0x00,0x00,0xbb,0xff,0xff,0xff,
0x62,0x00,0x00,0x00,0xa7,0xff,0xff,0xff,
0x5d,0x00,0x00,0x00,0xa1,0xff,0xff,0xff,
0xaa,0xff,0xff,0xff,0x66,0x00,0x00,0x00,
0xae,0xff,0xff,0xff,0x63,0x00,0x00,0x00,
0x5d,0x00,0x00,0x00,0xac,0xff,0xff,0xff,
0x62,0x00,0x00,0x00,0xa6,0xff,0xff,0xff,
0x5d,0x00,0x00,0x00,0x67,0x00,0x00,0x00,
0xaa,0xff,0xff,0xff,0x53,0x00,0x00,0x00,
0xa0,0xff,0xff,0xff,0x61,0x00,0x00,0x00,
0x5d,0x00,0x00,0x00,0x54,0x00,0x00,0x00,
0xae,0xff,0xff,0xff,0x66,0x00,0x00,0x00,
0x55,0x00,0x00,0x00,0x67,0x00,0x00,0x00,
0xbf,0xff,0xff,0xff]

input = ""
for i, value in enumerate(FLAG_BYTES):
    if i % 4 == 0:
        shifted = (value ^ 0x2a) - 0x18 
        char = chr(shifted)
        input += char

print(input) # ENSIBS{1st_y0u_sh4l1_n0t_5har3_fl4g5}
```
