#!/usr/bin/python

import sys

sys.path.insert(0, "/Users/shubbans/bansal/cryptopals/")

from Crypto.Hash import SHA
from Crypto.Hash import SHA256
from Crypto.Util.strxor import strxor_c

def hash_sha1(message):
  h = SHA.new()
  h.update(message)
  return h.hexdigest()

def hash_sha256(message):
  h = SHA256.new()
  h.update(message)
  return h.hexdigest()

def hmac(key, message, hash_function=hash_sha1, blocksize=64):
  if len(key) > blocksize:
    key = hash_function(key)
  if len(key) < blocksize:
    key += b'\x00' * (blocksize - len(key))

  opad = strxor_c(key, 0x5c)
  ipad = strxor_c(key, 0x36)

  return hash_function(opad + hash_function(ipad + message))