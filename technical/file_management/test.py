import hashlib

dk = hashlib.scrypt(b"password", salt=b"NaCl", n=16384, r=8, p=16)
print(dk.hex())

dk = hashlib.scrypt(b"password", salt=b"NaCl", n=16384, r=8, p=16)
print(dk.hex())
