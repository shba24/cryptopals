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
prefix = None
suffix = """Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
YnkK"""

def encryption_oracle(plaintext):
  global KEY
  global prefix
  if KEY is None:
    KEY = crypty.generate_key()
  if prefix is None:
    # I am getting integer between 0 to 100
    prefix = crypty.generate_key(key_size=randint(0,100))
    print "[*] Using Prefix of size : %d"%(len(prefix)/2)
  plaintext = crypty.pad_pkcs_7(prefix+plaintext+crypty.convert_b64_to_hex(suffix))
  return aes_ecb.infra.encrypt(plaintext, KEY)

def get_block_size():
  default_len = len(crypty.h2a(encryption_oracle(crypty.a2h(''))))
  for i in xrange(1,40):
    plaintext = crypty.a2h('A'*i)
    length = len(crypty.h2a(encryption_oracle(plaintext)))
    if length is not default_len:
      return length - default_len
  return None


def get_initial_size():
  default_len = len(crypty.h2a(encryption_oracle(crypty.a2h(''))))
  for i in xrange(1, 17):
    plaintext = crypty.a2h('A' * i)
    length = len(crypty.h2a(encryption_oracle(plaintext)))
    if length is not default_len:
      return default_len-i
  return None

def get_rep_block_idx(blocks):
  for i in xrange(len(blocks)-1):
    if blocks[i]==blocks[i+1]:
      return i
  return None

def get_prefix_size():
  for i in xrange(32,32+16):
    ciphertext = encryption_oracle(crypty.a2h('A'*i))
    idx = get_rep_block_idx(crypty.get_blocks(ciphertext))
    if idx is not None:
      return (16*idx)-i+32
  return None

def get_suffix(block_size, suffix_len, prefix_size):
  prefix_pad_len = (block_size - (prefix_size)%block_size)%block_size
  guessed_suffix = ""
  for idx in xrange(0,suffix_len):
    plaintext_len = prefix_pad_len + block_size - len(guessed_suffix)%block_size - 1
    actual_plaintext = 'X'*prefix_size + 'A'*plaintext_len + guessed_suffix
    ciphertext_1 = encryption_oracle(crypty.a2h('A'*plaintext_len))
    last_blk_idx = len(actual_plaintext)/block_size
    for c in xrange(0,256):
      ciphertext_2 = encryption_oracle(crypty.a2h('A'*prefix_pad_len+actual_plaintext[last_blk_idx*block_size:]+chr(c)))
      if crypty.get_blocks(ciphertext_2)[(prefix_pad_len+prefix_size)/block_size] == crypty.get_blocks(ciphertext_1)[last_blk_idx]:
        guessed_suffix+=chr(c)
        break
  return guessed_suffix

def solve():
  block_size = get_block_size()
  print "[+] Block Size : %d"%(block_size)

  initial_size = get_initial_size()
  print "[+] Prefix + Suffix Size : %d"%(initial_size)

  # Get the prefix size
  prefix_size = get_prefix_size()
  print "[+] Prefix Size : %d"%(prefix_size)

  suffix_size = initial_size - prefix_size
  print "[+] Suffix Size : %d"%(suffix_size)

  ## Byte-at-a-time ECB Decryption
  print get_suffix(block_size=block_size, suffix_len=suffix_size, prefix_size=prefix_size)
  return

if __name__=='__main__':
  solve()
