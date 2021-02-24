#!/usr/bin/env python3

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


# TODO implement the decode function
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


def shift(msg):
    j = len(msg) - 1
    output = ''

    for i in range(len(msg)//2):
        output += msg[i] + msg[j]
        j -= 1

    return output


# TODO implement the unshift function
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


if __name__ == '__main__':
    # shifted = shift('<REDACTED>')
    # hashed = encode(shifted)
    hashed = '4660۠ܰ4660ڀ٠װװސ23300۰ސݐ18640ܠݰװۀڠ18640۰ްؠѠȐՀȐа4660ѠȐѠߐА'
    # CODE HERE
    print(unshift(decode(hashed)))
