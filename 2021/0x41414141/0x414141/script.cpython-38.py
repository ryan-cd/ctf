# uncompyle6 version 3.7.4
# Python bytecode 3.8 (3413)
# Decompiled from: Python 3.8.5 (default, Jul 28 2020, 12:59:40) 
# [GCC 9.3.0]
# Embedded file name: ./script.py
# Compiled at: 2020-12-12 08:17:01
# Size of source mod 2**32: 481 bytes
import base64
secret = 'https://google.com'
cipher2 = [b'NDE=', b'NTM=', b'NTM=', b'NDk=', b'NTA=', b'MTIz', b'MTEw', b'MTEw', b'MzI=', b'NTE=', b'MzQ=', b'NDE=', b'NDA=', b'NTU=', b'MzY=', b'MTEx', b'NDA=', b'NTA=', b'MTEw', b'NDY=', b'MTI=', b'NDU=', b'MTE2', b'MTIw']
cipher1 = [base64.b64encode(str(ord(i) ^ 65).encode()) for i in secret]

## ~~ My own code added below to reverse engineer this ~~ ##
print(cipher1)
print(cipher2)
result = [chr(int(base64.b64decode(i).decode())^65) for i in cipher2]
print(''.join(result))


# b'NDE=' = base64.b64encode(str(ord(i) ^ 65).encode())
# base64.b64decode(b'NDE=').decode() = str(ord(i) ^ 65)
# int(base64.b64decode(b'NDE=').decode()) = ord(i)^65
# int(base64.b64decode(b'NDE=').decode())^65 = ord(i)
# chr(int(base64.b64decode(b'NDE=').decode())^65) = i