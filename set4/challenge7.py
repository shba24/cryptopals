#!/usr/bin/python

"""
Main Code
"""

import crypty
from crypty.hash import hmac
import time

def insecure_compare(str1, str2):
  assert len(str1) == len(str2)
  for i in xrange(len(str1)):
    if str1[i] is not str2[i]:
      return False
    time.sleep(0.05)
  return True

def solve():
  filename = "test.txt"
  key = crypty.generate_key()
  correct_hash = hmac(key.decode("hex"),open(filename,'r').read()).decode("hex")
  print "[*] Key : %s" % (correct_hash.encode("hex"))
  guessed_hash = ["\x00"]*20
  for i in xrange(20):
    found_byte = b''
    max_timetaken = 0
    for c in xrange(256):
      guessed_hash[i] = chr(c)
      timetaken = 0
      for j in xrange(1):
        t1 = time.time()
        insecure_compare("".join(guessed_hash), correct_hash)
        t2 = time.time()
        timetaken += (t2 - t1)*1000
      avg_timetaken = timetaken / 1.0
      if avg_timetaken > max_timetaken:
        found_byte = chr(c)
        max_timetaken = avg_timetaken
    print "Found next byte : %s" % (found_byte.encode("hex"))
    guessed_hash[i] = found_byte

  print "[+] Found Key : %s"%("".join(guessed_hash).encode("hex"))
  return

if __name__=='__main__':
  solve()