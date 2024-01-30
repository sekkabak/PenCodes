#! /usr/bin/python3

import sys

# def xor_encryption(text, key):
#     text = base64.b64decode(text).decode()
#     encrypted_text = ""

#     for i in range(len(text)):
#         encrypted_text += chr(ord(text[i]) ^ ord(key[i % len(key)]))
#     if sys.argv[1] == "-e":
#         return base64.b64encode(encrypted_text.encode())
#     if sys.argv[1] == "-d":
#         return encrypted_text

# if len(sys.argv) < 2:
#     exit("./xor.py -d 'MQEGKw4B'     - decryption\n./xor.py -e 'tested'       - encryption")

# plain_text = sys.argv[2].encode()
# if sys.argv[1] == "-e":
#     plain_text = base64.b64encode(plain_text)

# key = "thisismyverykulenckeee"
# if sys.argv[1] == "-e":
#     print(xor_encryption(plain_text, key).decode())
# if sys.argv[1] == "-d":
#     print(xor_encryption(plain_text, key))


sum = ""
for a in sys.argv[1]:
    sum = f"{sum}:{ord(a)+12}"
print(sum[1:])