"""
Main Code.
"""
import gmpy2
from crypty import a2h, h2a
from crypty.ciphers.rsa import rsa_init, encrypt, decrypt
from gmpy2 import mpz,powmod, t_mod, invert, iroot, mpz_random, t_div
from Crypto.Util.number import getPrime

rstate = gmpy2.random_state()

def solver():
    (e, d, N) = rsa_init(e=3)
    original_message = "A"*20
    enc = encrypt(original_message, e, N)
    msg = mpz(a2h(original_message), base=16)
    s = mpz_random(rstate, N)
    while s<2:
        s = mpz_random(rstate, N)
    new_enc = t_mod(pow(s, e, N) * enc , N)
    assert new_enc != enc
    dec = decrypt(new_enc, d, N)
    assert msg == t_mod(dec * invert(s, N), N)
    return

if __name__=='__main__':
    solver()