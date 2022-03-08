# -*- coding: utf-8 -*-
from ECDH_25519 import *
from binascii import hexlify as hex
import os
from hash_256 import hash_256
from skipjack import *
from RSA_Blind_Signature import *
import hashlib


# check password to start the system
hash_pass = "79f06f8fde333461739f220090a23cb2a79f6d714bee100d0e4b4af249294619"  # = 4444
password = input("Please enter your password: ")

if hash_256(password) != hash_pass:
    print("Wrong answer !")
    exit(1)

# generate a string of size 32 bytes (256 bits) suitable for cryptographic use in ECDH protocol.
a = os.urandom(32)
b = os.urandom(32)

# print Bob and Alice private keys (a - Alice private key, b- Bob private key).
print(f"\n\nAlice private key (a): \t{bytes_to_int(a)}")
print(f"\nBob private key (b):\t{bytes_to_int(b)}\n")


# find point n times x-point.
a_pub = base_point_mult(a)
b_pub = base_point_mult(b)


# print Bob and Alice public keys (aG - Alice public key, bG - Bob public key).
print("Alice public key (aG):\t", hex(a_pub.encode()))
print("\nBob public key (bG):\t", hex(b_pub.encode()))
print("\n")

# taking ag into hash function in order to avoid Oscar to interrupt the public key
hash_aG = hashlib.sha256(a_pub.encode())
print("\nHash(aG): ", hash_aG.hexdigest())

# digest hash(aG) to bytes and then to int in order to transfer to Bob
digest_hash_aG = int.from_bytes(hash_aG.digest(), 'big')
print("\n Digested hash(aG): ", digest_hash_aG)

# Bob creating keys and sending to Alice the public key
BobPublicKey, BobPrivateKey = keygen(2 ** 512)

# Alice creating blind msg with the public key of Bob and sending to Bob  to signature
r, blind_msg = blind(digest_hash_aG, BobPublicKey)   # = m'

# Bob signing on the blind message and sending this to Alice
blind_msg = int(blind_msg)
sign_msg = signature(blind_msg, BobPrivateKey)  # = s'

# Alice unblind the message and sending that to Bob
unblind_msg = unblind(sign_msg, r, BobPublicKey)  # = s

# Bob doing an unsignature (decryption) to message, and verification it.
unblind_msg = int(unblind_msg)
msg2 = signature(unblind_msg, BobPublicKey)

print("\nUnblinded msg raised by Bob public key(decrypt): ", msg2)
print("\n")

# check if hash(aG) == hash(aG) in order to verify its Alice
if (digest_hash_aG == int(msg2)):
    print("\nVerified Alice sent aG")
else:
    print("\nMaybe an Oscar in the system")

# multiply Alice private key with Bob public key - (a)*bG,
k_a = multscalar(a, b_pub)

# multiply Bob private key with Alice public key - (b)*aG.
k_b = multscalar(b, a_pub)

# print Bob and Alice shared key, expecting equal - (a)*bG = (a)*bG.
print("\nAlice shared key (a)bG:\n", hex(k_a.encode()))
print("\nBob shared key (b)aG:\n", hex(k_b.encode()))

if ((k_a == k_b) != True):
    print("Bob and Alice have a different keys!")
else:
    print("Bob and Alice have the same key.")

# Now that Alice received the key she can encrypt
encryptFile('car.jpg', hex(k_a.encode()))


print("Encrypt in process..44...")
#time.sleep(2)
print("Done.")

# Now that Bob received the key he can decrypt it
decryptFile('newFile_enc.jpg', hex(k_b.encode()))

print("Decrypt in process.....")
#time.sleep(2)
print("Done.")
