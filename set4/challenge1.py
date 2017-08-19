#!/usr/bin/python

## Importing crypty python library
import sys
sys.path.insert(0,"..")

"""
Main Code
"""

import crypty
from crypty.ciphers import ecb as aes_ecb
from crypty.ciphers import ctr as aes_ctr

key = crypty.generate_key()

def get_plaintext():
  fp = open("25.txt","r")
  ciphertext = crypty.convert_b64_to_hex("".join([l.strip() for l in fp.readlines()]))
  return aes_ecb.infra.decrypt(ciphertext, crypty.a2h("YELLOW SUBMARINE"))

def get_ciphertext():
  global key
  plaintext = get_plaintext()
  return aes_ctr.infra.encrypt(plaintext, key, 0)

def edit(ciphertext, key, offset, newtext):
  plaintext = list(aes_ctr.infra.decrypt(ciphertext, key, 0).decode("hex"))
  plaintext[offset:offset+len(newtext)] = list(newtext)
  return aes_ctr.infra.encrypt(crypty.a2h("".join(plaintext)), key, 0)

def attacker_function(ciphertext, offset, newtext):
  global key
  return edit(ciphertext, key, offset, newtext)

def solve():
  ciphertext = get_ciphertext().decode("hex")
  new_text = 'A'*len(ciphertext)
  new_ciphertext = attacker_function(new_text.encode("hex"), 0, new_text)
  key_stream = crypty.xor_hex_strings(new_ciphertext, new_text.encode("hex"))
  old_plaintext = crypty.xor_hex_strings(key_stream, ciphertext.encode("hex"))
  print old_plaintext.decode("hex")

if __name__=='__main__':
  solve()