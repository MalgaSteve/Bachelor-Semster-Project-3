import hashlib
import string
import binascii
import secrets
import os

def generate_random_string(length=16):
    characters = string.ascii_letters + string.digits
    random_string = ''.join(secrets.choice(characters) for _ in range(length))
    return random_string

m = hashlib.sha256()
i = generate_random_string(8)
print(i)
m.update(b"bob123"+i.encode("utf-8"))
print(m.hexdigest())
m = hashlib.sha256()
i = generate_random_string(8)
print(i)
m.update(b"bob123"+i.encode("utf-8"))
print(m.hexdigest())
