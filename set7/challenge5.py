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

def MDFunction(plaintext, IV, pad=True):
    hash = simplePadIVFn(IV)
    if pad:
        plaintext = simplePadMessageFn(a2h(plaintext))
    for block in get_blocks(a2h(plaintext), block_size=8):
        block = h2a(block)
        hash = simpleHashFn(block, hash)
    return hash

def findStatePrefixCollision(hashFn, iv1, iv2):
    hashToIV2Block = {}
    i = 0
    while i < 2**64:
        s = h2a(i2h(i)).ljust(8, "\x00")
        i+=1
        h = hashFn(s, iv1, pad=False)
        if h in hashToIV2Block:
            return (h, s, hashToIV2Block[h])

        h = hashFn(s, iv2, pad=False)
        hashToIV2Block[h] = s
    return None

def findNthBlock(hashFn, iv, n):
    prefix = b'\x00' * (8 * (n-1))
    prefixHash = hashFn(prefix, iv, pad=False)
    h, s, lastBlock = findStatePrefixCollision(hashFn, iv, prefixHash)
    return h, s, prefix+lastBlock

def findAllExpandableCollisions(hashFn, iv, k):
    blocks = []
    state = iv
    for i in xrange(k):
        state, s, finalS = findNthBlock(hashFn, state, 2**(k-i-1)+1)
        blocks.append([s, finalS])
    return state, blocks

def getIntermediateStates(message, hashFn, iv):
    state = iv
    for block in get_blocks(a2h(message)):
        block = h2a(block)
        state = hashFn(block, state, pad=False)
        yield state

def findCollision(message, hash, iv):
    blockCount = len(get_blocks(a2h(message)))
    k = blockCount.bit_length()
    prefixState, blocks = findAllExpandableCollisions(MDFunction, iv, k)
    intermediateStateIter = getIntermediateStates(message, MDFunction, iv)
    return ""

def solver():
    msg = h2a(generate_key(key_size=100))
    hash = MDFunction(msg, b'')
    pre_msg = findCollision(msg, hash, b'')
    return

if __name__=='__main__':
    solver()