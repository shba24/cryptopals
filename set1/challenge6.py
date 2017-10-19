#!/usr/bin/python

"""
Main Code
"""

import crypty
from crypty.ciphers import xor as xor_cipher

def get_ciphertext():
  fp = open("6.txt","r")
  result = ""
  for line in fp.readlines():
    result+=line.strip()
  return result

def solve():
  ciphertext = crypty.convert_b64_to_hex(get_ciphertext())

  ## Test to check hamming distance
  assert crypty.hamming_distance(crypty.a2h("this is a test"), crypty.a2h("wokka wokka!!!"))==37

  key_size = xor_cipher.attacks.keysize_estimator(ciphertext, 2, 40)[0][1]
  print "Trying for key size: %d" % (key_size)
  key = xor_cipher.attacks.brute_force(ciphertext, key_len=key_size)
  print "Found Key : %d : %s" % (len(crypty.h2a(key)), crypty.h2a(key))
  plaintext = xor_cipher.infra.decrypt(ciphertext, key)
  print "Plaintext : %s" % (crypty.h2a(plaintext))


if __name__=='__main__':
  solve()