#!/usr/bin/python

"""
Main Code
"""

import crypty

def solve():
    hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    return crypty.utils.convert_hex_to_b64(hex_string)

if __name__=='__main__':
    print solve()