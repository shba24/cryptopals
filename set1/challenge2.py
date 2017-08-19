#!/usr/bin/python

## Importing crypty python library
import sys
sys.path.insert(0,"..")

"""
Main Code
"""

import crypty

def solve():
  str1 = b"1c0111001f010100061a024b53535009181c"
  str2 = b"686974207468652062756c6c277320657965"
  return crypty.xor_hex_strings(str1,str2)

if __name__=='__main__':
  print solve()