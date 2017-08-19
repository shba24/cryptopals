## Importing crypty python library
import sys
sys.path.insert(0,"..")

"""
Main Code
"""

import crypty
from random import randint
from crypty.ciphers import ecb as aes_ecb

KEY = None
suffix = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

def encryption_oracle(plaintext):
  global KEY
  if KEY is None:
    KEY = crypty.generate_key()
  plaintext = crypty.pad_pkcs_7(plaintext+crypty.convert_b64_to_hex(suffix))
  return aes_ecb.infra.encrypt(plaintext, KEY)

def get_block_size():
  default_len = len(crypty.h2a(encryption_oracle(crypty.a2h(''))))
  for i in xrange(1,40):
    plaintext = crypty.a2h('A'*i)
    length = len(crypty.h2a(encryption_oracle(plaintext)))
    if length is not default_len:
      return length - default_len
  return

def get_suffix_size():
  default_len = len(crypty.h2a(encryption_oracle(crypty.a2h(''))))
  for i in xrange(1, 17):
    plaintext = crypty.a2h('A' * i)
    length = len(crypty.h2a(encryption_oracle(plaintext)))
    if length is not default_len:
      return default_len-i
  return

def get_suffix(block_size):
  suffix_len = get_suffix_size()
  guessed_suffix = ""
  for idx in xrange(0,suffix_len):
    prefix_len = block_size - len(guessed_suffix)%block_size - 1
    plaintext = 'A'*prefix_len + guessed_suffix
    ciphertext_1 = encryption_oracle(crypty.a2h('A'*prefix_len))
    last_blk_idx = len(plaintext)/block_size
    for c in xrange(0,256):
      ciphertext_2 = encryption_oracle(crypty.a2h(plaintext[last_blk_idx*block_size:]+chr(c)))
      if crypty.get_blocks(ciphertext_2)[0] == crypty.get_blocks(ciphertext_1)[last_blk_idx]:
        guessed_suffix+=chr(c)
        break
  return guessed_suffix


def solve():
  block_size = get_block_size()
  plaintext = crypty.a2h("A" * block_size)
  ciphertext = encryption_oracle(plaintext)
  ciphertext_blks = crypty.get_blocks(ciphertext, block_size=block_size)
  if ciphertext_blks[0] == ciphertext_blks[1]:
    print "[+] Detected ECB Encryption."
  print get_suffix(block_size)
  return

if __name__=='__main__':
  solve()