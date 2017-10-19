#!/usr/bin/python

"""
Main Code
"""

import crypty
from crypty.ciphers import ctr as aes_ctr
from crypty.ciphers import xor as xor_cipher

plaintexts = open("20.txt",'r').readlines()
key = crypty.generate_key()

def get_ciphertexts():
  ciphertexts = []
  for plaintext in plaintexts:
    plaintext = crypty.convert_b64_to_hex(plaintext)
    ciphertexts.append(aes_ctr.infra.encrypt(plaintext, key, 0))
  return ciphertexts

def solve():
  ciphertexts = get_ciphertexts()
  min_len  = min([len(c) for c in ciphertexts])
  ciphertexts = [c[:min_len] for c in ciphertexts]
  print "[+]Key Size : %d"%(min_len)
  key = xor_cipher.attacks.brute_force("".join(ciphertexts), key_len=min_len)
  print "[+]Found Key :  %s" %(key)
  plaintext = xor_cipher.infra.decrypt("".join(ciphertexts), key)
  print "Partial Plaintext : %s" % (crypty.h2a(plaintext))

if __name__=='__main__':
  solve()