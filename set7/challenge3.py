"""
Main Code
"""

import zlib
import crypty
import string
from crypty import generate_key, a2h, h2a, pad_pkcs_7
from crypty.ciphers import cbc as aes_cbc

session_bytes = string.ascii_letters + string.digits + "+/="
padding_bytes = '!@#$%^&*()-`~[]{}'

def build_request(msg):
    request = """POST / HTTP/1.1
Host: hapless.com
Cookie: sessionid=TmV2ZXIgcmV2ZWFsIHRoZSBXdS1UYW5nIFNlY3JldCE=
Content-Length: %d
%s"""%(len(msg), msg)
    return request

# oracle(P) -> length(encrypt(compress(format_request(P))))
def oracle(msg):
    key = generate_key()
    iv = generate_key()
    request = build_request(msg)
    compressed_request = zlib.compress(request)
    encrypted_request = aes_cbc.infra.encrypt_manual(pad_pkcs_7(a2h(compressed_request)), key, iv)
    return len(encrypted_request)

# Lets consider compressed string "AAAAAAAAAAAAAAA~" which is of length 16 bytes.
# When we encrypt this compressed string with cbc, cbc will add paddint to it of
# 16 bytes, which will increase the size of the final encrypted string. But suppose
# if we could make this string of size 15 using the compression which will look for
# similar string, the cbc padding would be of size 1, which make the final encryted
# string of size less than the previous encryted string as the new encrypted string
# has 1 less block of size 16 bytes. This is what we are looking for, first we make
# the compressed string similar to inital string of 16 bytes(figurately) and then
# replace few guessed char in next string, and if that decreases the final encrypted
# string length than compression have found a similar string.
# If you dont get it, just assume what I am saying, you are not
# worthy of the truth.
def getPadding(known_str):
    padding = ""
    len1 = oracle(known_str)
    for ch in list(padding_bytes):
        padding += ch
        len2 = oracle(padding + known_str)
        if len2 > len1:
            return padding

def getNextByte(known_str):
    final_guess = ""
    prev_sz = 999999
    padding = getPadding(("sessionid="+known_str+"~")*10)
    for ch in list(session_bytes):
        next_guess = "sessionid=" + known_str + ch
        new_sz = oracle(padding + next_guess * 10)
        if new_sz<prev_sz:
            prev_sz = new_sz
            final_guess = ch
    return final_guess

def solver():
    known_str = ""
    for i in xrange(44):
        known_str += getNextByte(known_str)
    print known_str
    return known_str

if __name__=='__main__':
    solver()