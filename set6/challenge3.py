"""
Main Code.
"""
from crypty import a2h, h2a
from gmpy2 import is_prime, mpz, mpz_random, random_state, invert, t_mod, powmod
from Crypto.Random import random
from Crypto.Hash import SHA
from Crypto.Util.number import getPrime

rstate = random_state()

def getSHA1(MSG):
  h = SHA.new()
  h.update(MSG)
  return h.hexdigest()

def generatePrime(bits):
  return mpz(getPrime(bits))

def genP(L, q):
    minK = (pow(2, L-1) + (q-1))//q
    maxK = (pow(2, L) - 1)//q
    while True:
        k = mpz_random(rstate, maxK - minK) + minK
        p = k*q + 1
        if is_prime(p):
            return (k, p)

def genG(p, q, k):
    h = 2
    while h<p-1:
        g = pow(h, k, p)
        if g!=1:
            return g
        h+=1
    return None

def genParams(L, N):
    q = generatePrime(N)
    k, p = genP(L, q)
    g = genG(p, q, k)
    return (p, q, g)

def genKeys(p, q, g, B=None):
    priv = None
    if B is None:
        d = mpz_random(rstate, q-1) + 1
        priv = d
        B = pow(g, d, p)
    pub = (p, q, g, B)
    return (pub, priv)

def signDSA(message, pub, priv, kE=None):
    (p, q, g, B) = pub
    d = priv
    H = mpz(getSHA1(message), base=16)
    while True:
        if kE is None:
            # Ephemeral key
            kE = mpz_random(rstate, q-1) + 1
        r = t_mod(pow(g, kE, p), q)
        if r == 0:
            continue
        s = t_mod(((H + (d*r)) * invert(kE, q)), q)
        if s == 0:
            continue
        return (r, s)
    return (None, None)

def verifySign(sig, message, pub):
    (p, q, g, B) = pub
    (r, s) = sig
    s_inv = invert(s, q)
    H = mpz(getSHA1(message), base=16)
    u1 = t_mod(s_inv * H, q)
    u2 = t_mod(s_inv * r, q)
    v = t_mod(t_mod(powmod(g, u1, p) * powmod(B, u2, p), p), q)
    if v == t_mod(r, q):
        return True
    else:
        return False
    return False

def BruteForceK(message, pub, r, s, k_min, k_max):
    (p, q, g, B) = pub
    H = mpz(getSHA1(message), base=16)
    for k in xrange(k_min, k_max):
        r_inv = invert(r, q)
        d = t_mod(((s*k) - H) * r_inv, q)
        if powmod(g, d, p) == B:
            print "[+] Found the Private Key."
            print "[+] Key(k) : %s, Priv(d) = %s"%(hex(k), hex(d))
            return (k, d)
    return (None, None)

def solver():
    message = b"""For those that envy a MC it can be hazardous to your health
So be friendly, a matter of life and death, just like a etch-a-sketch
"""
    L = mpz(1024)
    N = 160
    # (p, q, g) = genParams(L, N)
    p = mpz("800000000000000089e1855218a0e7dac38136ffafa72eda7859f2171e25e65eac698c1702578b07dc2a1076da241c76c62d374d8389ea5aeffd3226a0530cc565f3bf6b50929139ebeac04f48c3c84afb796d61e5a4f9a8fda812ab59494232c7d2b4deb50aa18ee9e132bfa85ac4374d7f9091abc3d015efc871a584471bb1", base=16)
    q = mpz("f4f47f05794b256174bba6e9b396a7707e563c5b", base=16)
    g = mpz("5958c9d3898b224b12672c0b98e06c60df923cb8bc999d119458fef538b8fa4046c8db53039db620c094c9fa077ef389b5322a559946a71903f990f1f7e0e025e2d7f7cf494aff1a0470f5b64c36b625a097f1651fe775323556fe00b3608c887892878480e99041be601a62166ca6894bdd41a7054ec89f756ba9fc95302291", base=16)
    B = mpz("84ad4719d044495496a3201c8ff484feb45b962e7302e56a392aee4abab3e4bdebf2955b4736012f21a08084056b19bcd7fee56048e004e44984e2f411788efdc837a0d2e5abb7b555039fd243ac01f0fb2ed1dec568280ce678e931868d23eb095fde9d3779191b8c0299d6e07bbb283e6633451e535c45513b2d33c99ea17", base=16)
    xH = "d2d0714f014a9784047eaeccf956520045c45265"
    if getSHA1(message) != xH:
        print "[-] Not the correct message string"
        return
    (pub, priv) = genKeys(p, q, g, B)
    # sig = signDSA(message, pub, priv)
    r = mpz("548099063082341131477253921760299949438196259240", base=10)
    s = mpz("857042759984254168557880549501802188789837994940", base=10)
    sig = (r, s)
    if verifySign(sig, message, pub):
        print "[+] Signature verified."
    else:
        print "[-] Signature not verified."
    k, priv = BruteForceK(message, pub, r, s, 0, 2**16)
    xPriv = mpz("0954edd5e0afe5542a4adf012611a91912a3ec16", base=16)
    if xPriv == mpz(getSHA1(hex(priv)[2:]), base=16):
        print "[+] Private Key Found."
    else:
        print "[-] Private Key not Found."
        return
    (_r, _s) = signDSA(message, pub, priv, kE=k)
    if _r != r or _s != s:
        print "[-] Wrong."
    else:
        print "[+] Done. Check Complete."
    return

if __name__=='__main__':
    solver()