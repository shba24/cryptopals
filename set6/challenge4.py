"""
Main Code.
"""
import re
import gmpy2
import itertools
from crypty import a2h, h2a, i2h
from crypty.ciphers.rsa import rsa_init, encrypt, decrypt
from gmpy2 import mpz,powmod, t_mod, invert, iroot, mpz_random, t_div
from Crypto.Hash import SHA

def getSHA1(MSG):
  h = SHA.new()
  h.update(MSG)
  return h.hexdigest()

def parseMessage(msg_blob):
    msg = re.match('^msg: (.*)', msg_blob[0]).group(1).encode('ascii')
    m = mpz(re.match('^m: (.*)', msg_blob[3]).group(1), base=16)
    H = mpz(getSHA1(msg), base=16)
    if m != H:
        print "[-] Message not parsed correctly."
        return (None, None, None, None)
    s = mpz(re.match('^s: (.*)', msg_blob[1]).group(1), base=10)
    r = mpz(re.match('^r: (.*)', msg_blob[2]).group(1), base=10)
    return (msg, s, r, m)

def getMessages():
    lines = list(open("44.txt", "r").readlines())
    messages = [lines[i:i+4] for i in xrange(0, len(lines), 4)]
    return [parseMessage(m) for m in messages]

def checkForSameK(messages, pub):
    (p, q, g, B) = pub
    for (msg1, msg2) in itertools.combinations(messages, 2):
        (_, s1, r1, m1) = msg1
        (_, s2, r2, m2) = msg2
        if r1!=r2:
            continue
        ds_inv = invert(s1 - s2, q)
        k = t_mod(ds_inv * (m1-m2), q)
        r1_inv = invert(r1, q)
        r2_inv = invert(r2, q)
        d1 = t_mod(((s1*k) - m1) * r1_inv, q) % q
        d2 = t_mod(((s2*k) - m2) * r2_inv, q) % q
        if d1==d2:
            print "[+] Found the messages. "
            return (msg1, msg2, d1)
    return

def solver():
    p = mpz("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", base=16)
    q = mpz("f4f47f05794b256174bba6e9b396a7707e563c5b", base=16)
    g = mpz("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", base=16)
    B = mpz("2d026f4bf30195ede3a088da85e398ef869611d0f68f0713d51c9c1a3a26c95105d915e2d8cdf26d056b86b8a7b85519b1c23cc3ecdc6062650462e3063bd179c2a6581519f674a61f1d89a1fff27171ebc1b93d4dc57bceb7ae2430f98a6a4d83d8279ee65d71c1203d2c96d65ebbf7cce9d32971c3de5084cce04a2e147821", base=16)
    messages = getMessages()
    pub = (p, q, g, B)
    (msg1, msg2, d) = checkForSameK(messages, pub)
    H = "ca8f6f7c66fa362d40760d135b763eb8527d3d52"
    if getSHA1(hex(d)[2:]) == H:
        print "[+] Correct private key(d) found : %s"%(hex(d))
    else:
        print "[-] Got incorrect private key."
    return

if __name__=='__main__':
    solver()