#!/usr/bin/python


## Importing crypty python library
import sys
sys.path.insert(0,"..")

"""
Main Code
"""

from crypty.ciphers import xor as xor_cipher
import string

def solve():
  fp = open("4.txt","r")
  result = []
  lines = fp.readlines()
  for idx,line in enumerate(lines):
    line = line.strip()
    key = xor_cipher.attacks.brute_force(line, key_len=1)
    plaintext = xor_cipher.infra.decrypt(line, key)
    if all(c in string.printable for c in plaintext):
      result.append(plaintext)
      print "Line : %d : Length : %d Plaintext : %s" %(idx,len(result[-1]),result[-1])
  return result

if __name__=='__main__':
  solve()