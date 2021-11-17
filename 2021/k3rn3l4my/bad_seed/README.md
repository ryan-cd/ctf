# Bad Seed
This challenge provides a binary to practice on locally before running our exploit on the remote host. We'll use Ghidra to decompile the binary to see how it works. 

The main entry point shows that we'll need to tackle a series of questions:

```c
undefined8 main(EVP_PKEY_CTX *param_1)

{
  init(param_1);
  question_one();
  question_two();
  question_three();
  gz();
  return 0;
}
```

## Question 1

Let's look at the first question (trimming the code to the relevant portion):

```c
void question_one(void)

{
  // snipped
  local_20 = 6.035077;
  local_1c = 4000;
  local_24 = 0;
  local_18 = 0;
  // snipped
  local_18 = (int)((float)local_1c / local_20);
  puts("how heavy is an asian elephant on the moon?");
  __isoc99_scanf(&DAT_00402034,&local_24);
  if (local_18 != local_24) {
    puts("wrong bye bye");
    exit(0);
  }
  puts("\ngreat 2nd question:");
  puts("give me the rand() value");
  // snipped
}
```

The first question, `how heavy is an asian elephant on the moon?`, has an answer of `4000/6.035077`. After casting to `int`, this equals `662`. Let's get started on the solve script!

```python
#!/usr/bin/env python3

from pwn import *

binary = context.binary = ELF('./badseed')

if args.REMOTE:
    io = remote('ctf.k3rn3l4rmy.com', 2200)
else:
    io = process(binary.path)

# Question 1
io.recvline()
io.sendline(str(662).encode())
io.recvuntil(b'give me the rand() value\n')
```

The script has a flag to either run locally or on the remote. It will send our first solution and then exit.

```sh
 ./exploit.py DEBUG       
[DEBUG] Received 0x2c bytes:
    b'how heavy is an asian elephant on the moon?\n'
[DEBUG] Sent 0x4 bytes:
    b'662\n'
[DEBUG] Received 0x2e bytes:
    b'\n'
    b'great 2nd question:\n'
    b'give me the rand() value\n'
```

## Question 2

Let's look at the function for the next question:

```c
void question_two(void)

{
  // snipped
  int local_24;
  int local_20;
  int local_1c;
  time_t local_18;
  // snipped

  local_18 = time((time_t *)0x0);
  __isoc99_scanf(&DAT_00402034,&local_24);
  srand((uint)local_18);
  local_20 = rand();
  local_1c = rand();
  if (local_1c != local_24) {
    puts("wrong bye bye");
    exit(0);
  }
  puts("great 3rd question:");
  puts("no hint this time... you can do it?!");
  // snipped
}
```
This function starts by calling `srand(time(NULL))`. This will set the random number generator seed to the current time. Then it generates two random numbers, and then checks that our answer equals the second random number. 

Python is able to call C functions. If we mimic the call to set the seed, and the two random number generations, we can actually obtain the same random number the question generates! We'll just have to generate our numbers at the same time the quiz code is doing it. 

We can add the `libc` library to our code to prepare for generating some random numbers:

```python
import ctypes

libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libm.so.6')
```

And now, let's generate and send the number:

```python
# Question 2
libc.srand(libc.time(None))
number1 = libc.rand()
number2 = libc.rand()
io.sendline(str(number2).encode())
io.recvuntil(b'no hint this time... you can do it?!\n')
```

Quick test:

```sh
./exploit.py DEBUG
[DEBUG] Received 0x2c bytes:
    b'how heavy is an asian elephant on the moon?\n'
[DEBUG] Sent 0x4 bytes:
    b'662\n'
[DEBUG] Received 0x2e bytes:
    b'\n'
    b'great 2nd question:\n'
    b'give me the rand() value\n'
[DEBUG] Sent 0xb bytes:
    b'2137537274\n'
[DEBUG] Received 0x39 bytes:
    b'great 3rd question:\n'
    b'no hint this time... you can do it?!\n'
```

## Question 3
Almost there. Let's look at the last question:

```c
void question_three(void)

{
  // snipped
  int local_2c;
  uint local_28;
  int local_24;
  int local_20;
  int local_1c;
  time_t local_18;
  // snipped
  local_18 = time((time_t *)0x0);
  srand((uint)local_18);
  local_28 = rand();
  srand(local_28);
  local_24 = rand();
  local_20 = (int)local_28 / local_24;
  local_1c = local_20 % 1000;
  __isoc99_scanf(&DAT_00402034,&local_2c);
  if (local_1c != local_2c) {
    puts("wrong bye bye");
    exit(0);
  }
  puts("great heres your shell");
  // snipped
}
```

After this function ends, the program calls the `gz` function that gives a shell:

```c
void gz(void)

{
  system("/bin/sh");
  return;
}
```

The `question_three` function does the following:
1. Seeds the random number generator with `time(NULL)`.
1. Generates a random number, and then seeds the RNG with that value.
1. Generates a second random number.
1. Calculates the first random number divided by the second. Then checks that our answer equals the remainder of dividing that value by 1000.

We can accomplish that with some code similar to our answer to question 2:

```python
# Question 3
libc.srand(libc.time(None))
number1 = libc.rand()
libc.srand(number1)
number2 = libc.rand()
result = (number1 // number2) % 1000
io.sendline(str(result).encode())

io.interactive()
```

Now, we can run the full script on the remote server, and obtain a shell!

```sh
 ./exploit.py REMOTE 
[*] Switching to interactive mode
great heres your shell
$ ls
flag.txt
run
$ cat flag.txt
flag{i_0_w1th_pwn70ols_i5_3a5y}
```

Flag captured! This took a couple tries since the latency of the request can lead to us sending obsolete random number values.

## Solution Script

```python
#!/usr/bin/env python3

from pwn import *
import ctypes

libc = ctypes.CDLL('/lib/x86_64-linux-gnu/libm.so.6')
binary = context.binary = ELF('./badseed')

if args.REMOTE:
    io = remote('ctf.k3rn3l4rmy.com', 2200)
else:
    io = process(binary.path)

# Question 1
io.recvline()
io.sendline(str(662).encode())
io.recvuntil(b'give me the rand() value\n')

# Question 2
libc.srand(libc.time(None))
number1 = libc.rand()
number2 = libc.rand()
io.sendline(str(number2).encode())
io.recvuntil(b'no hint this time... you can do it?!\n')

# Question 3
libc.srand(libc.time(None))
number1 = libc.rand()
libc.srand(number1)
number2 = libc.rand()
result = (number1 // number2) % 1000
io.sendline(str(result).encode())

io.interactive()
# flag{i_0_w1th_pwn70ols_i5_3a5y}
```
