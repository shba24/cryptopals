#!/usr/bin/python

"""
Main Code
"""

from crypty.hash import sha1
from Crypto.Hash import SHA

def authenticate(message, key, MAC):
  h = SHA.new()
  h.update(key+message)
  sha1_hex = h.hexdigest()
  if sha1_hex!=MAC:
    print "UNAUTHORISED"
    return False
  else:
    print "AUTHORISED"
    return True

def solve():
  return

if __name__=='__main__':
  solve()