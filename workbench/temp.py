#!./dns/bin/python3

import hashlib 
import hmac 
import os
import base64


if __name__ == '__main__':
    barray = os.urandom(16) # <- случайная 16 байтная последовательность
    secret = os.urandom(2) # <- случайный ключ
    raw = hmac.new(
        secret, # <- ключ
        msg=barray, # <- хэщируемая последовательность
        digestmod=hashlib.sha256 # <- алгоритм
    ).digest()
    tsig = base64.b64encode(raw) # <- упаковываем в base64
    print(tsig.decode()) # <- выводим строку