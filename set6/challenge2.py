"""
Main Code.
"""
import re
import gmpy2
from crypty import a2h, h2a, i2h
from crypty.ciphers.rsa import rsa_init, encrypt, decrypt
from gmpy2 import mpz,powmod, t_mod, invert, iroot, mpz_random, t_div
from Crypto.Hash import SHA

def getSHA1(MSG):
  h = SHA.new()
  h.update(MSG)
  return h.hexdigest()

def generateSignature(message, d, N):
    digest = getSHA1(message)
    block = b'\x00\x01' + (b'\xff' * (128 - len(digest) - 3)) + b'\x00' + digest
    signature = encrypt(block, d, N)
    return signature

def verifySignature(message, signature, e, N):
    block = b'\x00' + h2a(i2h(encrypt(signature, e, N)))
    print a2h(block)
    r = re.compile(b'\x00\x01\xff+?\x00(.{40})', re.DOTALL)
    m = r.match(block)
    if not m:
        return False
    digest = m.group(1)
    return digest == getSHA1(message)

def forgeSignature(message):
    digest = getSHA1(message)
    block = b'\x00\x01\xff\x00' + digest + (b'\x00' * (128 - len(digest) - 4))
    signature = iroot(mpz(a2h(block), base=16), 3)[0] + 1
    print i2h(pow(signature, 3))
    return signature

def solver():
    msg = b'hi mom'
    (e, d, N) = rsa_init(e=3, key_size=2048)
    signature = generateSignature(msg, d, N)
    if not verifySignature(msg, signature, e, N):
        print "[-] Signature not matching."
    else:
        print "[+] Signature matched."
    sign = forgeSignature(msg)
    if not verifySignature(msg, sign, e, N):
        print "[-] Forged signature is wrong."
    else:
        print "[+] Forged signature is correct."
    return

if __name__=='__main__':
    solver()