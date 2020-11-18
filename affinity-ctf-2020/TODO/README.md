# TODO
### Category: Reverse Engineering

This challenge included a python file with a hidden message encoded in a string. The `encode` and `shift` methods were provided and the `decode` and `unshift` methods were left for the player to implement.

One of the key intuitions to coming up with a solution was understanding what the `encode` funtion was doing.

```python
def encode(msg):
    output = ''

    for i in range(len(msg)):
        temp = ord(msg[i]) * 0x40
        temp = temp >> 4
        if 0xc0 <= temp < 0xe8:
            output = str(int(msg[i]) * 0x1234) + output
        else:
            output = chr(ord(msg[i]) * 0x10) + output

    return output
```

For each character in the string, if it is part of `[1-9]` it becomes `str(int(msg[i]) * 0x1234)`. Otherwise it becomes `chr(ord(msg[i]) * 0x10)`. Each of the encoded items gets built into a string that is in the reversed order of the input.

For the shift function:
```python
def shift(msg):
    j = len(msg) - 1
    output = ''

    for i in range(len(msg)//2):
        output += msg[i] + msg[j]
        j -= 1

    return output
```

This is shuffling the string by interleaving elements from the front with elements from the back. For example:

```python
>>> shift('0123456789')
'0918273645'
```

My decode and unshift functions apply the inverse operations:

```python
def decode(msg):
    # Since numbers encode into multiple characters, it is easier to do a first pass decoding them first
    for i, encoded_number in enumerate(['4660', '9320', '13930', '18640', '23300', '27960', '32620', '37280', '41940']):
        msg = msg.replace(encoded_number, str(i+ 1))

    result = ''
    for i in range(len(msg)):
        if msg[i] in '123456789':
            result += msg[i]
        else:
            result += chr(ord(msg[i]) // 0x10)
    return result[::-1]
```

```python
def unshift(msg):
    result = ''
    back = ''
    for i in range(len(msg)):
        if i % 2 == 0:
            result += msg[i]
        else:
            back += msg[i]
    result += back[::-1]
    return result    
```

Put together:

```sh
./task.py 
AFFCTF{4lw4y5_f1n1sh_your_job!!1!}
```