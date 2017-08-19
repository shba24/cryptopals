#!/usr/bin/python

## Importing crypty python library
import sys
sys.path.insert(0,"..")

"""
Main Code
"""

from crypty.rng.mersenne_twister import MT19937


if __name__ == '__main__':

    m = MT19937(0)
    n = MT19937(0)
    if [m.random() for __ in range(700)] == [n.random() for __ in range(700)]:
        print "Mersenne same seed test passed"
    else:
        print "Mersenne same seed test failed"

    m = MT19937(0)
    n = MT19937(1)
    if [m.random() for __ in range(700)] != [n.random() for __ in range(700)]:
        print "Mersenne different seed test passed"
    else:
        print "Mersenne different seed test failed"