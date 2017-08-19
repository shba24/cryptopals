"""
Main Code
"""

# Not fully complete but I got the idea.

import zlib
import crypty
import string
import random
from Crypto.Cipher import Blowfish
from crypty import generate_key, a2h, h2a, pad_pkcs_7, get_blocks, i2h
from crypty.ciphers import ecb as aes_ecb

simpleHashLength = 2

def simpleHashFn(message, state):
    print a2h(message), a2h(state)
    cipher = Blowfish.new(state, Blowfish.MODE_ECB)
    newState = cipher.encrypt(message)
    return newState

def simplePadIVFn(iv):
    if len(iv) < simpleHashLength:
        return iv.ljust(simpleHashLength, "\x00")
    else:
        return iv[:simpleHashLength]

def simplePadMessageFn(message_hex):
    return h2a(pad_pkcs_7(message_hex, block_size=8))

def findOneBlockCollision(hashFn, iv, iterator):
    hashDB = {}
    for msg in iterator:
        hash = hashFn(msg, iv, pad=False)
        if hash in hashDB:
            return hash, msg, hashDB[hash]
        hashDB[hash] = msg
    return None, None, None

def generateCollision(hashFn, iv, depth):
    hash, m1, m2 = findOneBlockCollision(hashFn, iv, (h2a(i2h(i)).ljust(8, '\x00') for i in range(0, 2**16)))
    collisions = [m1, m2]
    for i in xrange(5):
        hash, m1, m2 = findOneBlockCollision(hashFn, hash, (h2a(i2h(i)).ljust(8, '\x00') for i in range(0, 2**16)))
        collisions = [collisions[0]+m1, collisions[1]+m2]
    return

def MDFunction1(plaintext, IV, pad=True):
    hash = simplePadIVFn(IV)
    if pad:
        plaintext = simplePadMessageFn(plaintext)
    for block in get_blocks(a2h(plaintext), block_size=8):
        block = h2a(block)
        hash = simpleHashFn(block, hash)
    return hash

def solver():
    simpleHash = MDFunction1
    generateCollision(simpleHash, b'', 5)
    return

if __name__=='__main__':
    solver()