#!/usr/bin/python

"""
Main Code
"""

import crypty

def solve():
  print crypty.pad_pkcs_7(crypty.a2h("YELLOW SUBMARINE"), block_size=20)

if __name__=='__main__':
  solve()