# Dice Roll
**Category: Cryptography**

This challenge lets us connect to a server to play a dice roll guessing application:

```
$ nc challenge.nahamcon.com 30260

              _______
   ______    | .   . |\
  /     /\   |   .   |.\
 /  '  /  \  | .   . |.'|
/_____/. . \ |_______|.'|
\ . . \    /  \ ' .   \'|
 \ . . \  /    \____'__\|
  \_____\/

      D I C E   R O L L


0. Info
1. Shake the dice
2. Roll the dice (practice)
3. Guess the dice (test)

> 2
Rolling the dice... the sum was:
509869294

0. Info
1. Shake the dice
2. Roll the dice (practice)
3. Guess the dice (test)

> 3
Guess the dice roll to win a flag! What will the sum total be?
>
```

Looks like the program generates random numbers, and we need to correctly predict the upcoming number to win the flag.

The source code was provided:

```python
#!/usr/bin/env python3

import random
import os

banner = """
              _______
   ______    | .   . |\\
  /     /\\   |   .   |.\\
 /  '  /  \\  | .   . |.'|
/_____/. . \\ |_______|.'|
\\ . . \\    /  \\ ' .   \\'|
 \\ . . \\  /    \\____'__\\|
  \\_____\\/

      D I C E   R O L L
"""

menu = """
0. Info
1. Shake the dice
2. Roll the dice (practice)
3. Guess the dice (test)
"""

dice_bits = 32
flag = open('flag.txt').read()

print(banner)

while 1:
	print(menu)

	try:
		entered = int(input('> '))
	except ValueError:
		print("ERROR: Please select a menu option")
		continue

	if entered not in [0, 1, 2, 3]:
		print("ERROR: Please select a menu option")
		continue

	if entered == 0:
		print("Our dice are loaded with a whopping 32 bits of randomness!")
		continue

	if entered == 1:
		print("Shaking all the dice...")
		random.seed(os.urandom(dice_bits))
		continue

	if entered == 2:
		print("Rolling the dice... the sum was:")
		print(random.getrandbits(dice_bits))
		continue

	if entered == 3:
		print("Guess the dice roll to win a flag! What will the sum total be?")
		try:
			guess = int(input('> '))
		except ValueError:
			print("ERROR: Please enter a valid number!")
			continue

		total = random.getrandbits(dice_bits)
		if guess == total:
			print("HOLY COW! YOU GUESSED IT RIGHT! Congratulations! Here is your flag:")
			print(flag)
		else:
			print("No, sorry, that was not correct... the sum total was:")
			print(total)

		continue
```

The key takeaway is that we are using `random.getrandbits(32)` to generate the random numbers. Python's pseudonumber generator uses the Mersenne Twister under the hood. We can use RandCrack to take numbers from the dice program as input and predict the next value. From the RandCrack docs:

> This cracker works as the following way. It obtains first 624 32 bit numbers from the generator and obtains the most likely state of Mersenne Twister matrix, which is the internal state. From this point generator should be synchronized with the cracker.

I wrote this program to take in the required 624 integers and predict the next one:

```python
#!/usr/bin/env python3

from progress.bar import Bar
from pwn import *
from randcrack import RandCrack

REQUIRED_INTEGER_COUNT = 624

rc = RandCrack()
io = remote('challenge.nahamcon.com', 30260)

with Bar('Progress', max=REQUIRED_INTEGER_COUNT) as progress_bar:
    for i in range(REQUIRED_INTEGER_COUNT):
        io.sendlineafter('> ', '2') # Roll the dice
        io.recvline()
        number = int(io.recvline())
        rc.submit(number)
        progress_bar.next()

io.sendlineafter('> ', '3') # Start a prediction
prediction = rc.predict_getrandbits(32)
io.sendlineafter('> ', str(prediction))
io.interactive()
```

Output:
```
$ ./exploit.py
[+] Opening connection to challenge.nahamcon.com on port 30260: Done
Progress |################################| 624/624
[*] Switching to interactive mode
HOLY COW! YOU GUESSED IT RIGHT! Congratulations! Here is your flag:
flag{e915b62b2195d76bfddaac0160ed3194}
```
