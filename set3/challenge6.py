#! /usr/bin/env python

## Importing crypty python library
import sys
sys.path.insert(0,"..")

"""
Main Code
"""

from crypty.rng.mersenne_twister import MT19937
import time
from random import randint

def get_random():
  time.sleep(randint(40,100))
  m = MT19937(int(time.time()))
  time.sleep(randint(40,100))
  return m.random()

def crack_seed(value):
  possible_seeds = []
  current_time = int(time.time())
  for seed in range(current_time - 200, current_time+1):
    m = MT19937(seed)
    if m.random() == value:
      possible_seeds.append(seed)
  return possible_seeds

print crack_seed(get_random())