#!/usr/bin/python

"""
Main Code
"""

from crypty.hash import sha1
import struct
import crypty
from random import randint

key = crypty.generate_key(key_size=randint(0,40)).decode("hex")

def validate(message, key, digestMAC):
  return sha1.authenticate(message, key, digestMAC)

def pad(message):
  l = (len(message)) * 8
  message+= b'\x80'
  message+= b'\x00' * ((56 - (len(message) % 64)) % 64)
  message += struct.pack('>Q', l)
  return message

def solve():
  message = "comment1=cooking%20MCs;userdata=foo;comment2=%20like%20a%20pound%20of%20bacon"
  hash = sha1.sha1_hexdigest(key+message)
  hasher = sha1.SHA1(crypty.get_sha1_regs(hash))
  hasher.update(";admin=true;", len(pad(key+message)+";admin=true;"))
  new_hash = hasher.hexdigest()
  assert sha1.sha1_hexdigest(pad(key+message)+";admin=true;") == new_hash
  ## new_hash is an hash of key+message+glue_padding+";admin=true:"
  for i in xrange(0,40):
    if validate(pad("A"*i+message)[i:]+";admin=true;", key, new_hash):
      print "[+] Found Key length : %d"%(i)
  return

if __name__=='__main__':
  solve()