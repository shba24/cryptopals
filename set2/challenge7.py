## Importing crypty python library
import sys

sys.path.insert(0,"..")

"""
Main Code
"""

import crypty

def solve():
  try:
    print crypty.h2a(crypty.unpad_pkcs_7(crypty.a2h("ICE ICE BABY\x04\x04\x04\x04")))
  except Exception as e:
    print e
  try:
    print crypty.h2a(crypty.unpad_pkcs_7(crypty.a2h("ICE ICE BABY\x05\x05\x05\x05")))
  except Exception as e:
    print e
if __name__=='__main__':
  solve()