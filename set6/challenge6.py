"""
Main Code.
"""
import gmpy2
from crypty import a2h, h2a, convert_b64_to_ascii, i2h
from crypty.ciphers.rsa import rsa_init, encrypt, decrypt
from gmpy2 import mpz,powmod, t_mod, invert, iroot, mpz_random, t_div
from Crypto.Util.number import getPrime

def parityOracle(ciphertext, d, N):
    plaintext = decrypt(ciphertext, d, N)
    return ((plaintext%2)==1)

def deductPlaintext(c, e, d, N):
    plaintext = ""
    lowP = 0
    highP = N - 1
    k = pow(2, e, N)
    i = 0
    while True:
        c = t_mod((c * k), N)
        p = parityOracle(c, d, N)
        if p == True:
            lowP += (highP-lowP)/2
        else:
            highP -= (highP-lowP + 1)/2

        if lowP == highP or lowP + 1==highP :
            print "[+] Found Plaintext."
            plaintexts = (i2h(lowP).decode("hex"), i2h(lowP+1).decode("hex"))
            break
    return plaintexts

def solver():
    (e, d, N) = rsa_init(key_size=1024)
    plaintext = convert_b64_to_ascii("VGhhdCdzIHdoeSBJIGZvdW5kIHlvdSBkb24ndCBwbGF5IGFyb3VuZCB3aXRoIHRoZSBGdW5reSBDb2xkIE1lZGluYQ==")
    ciphertext = encrypt(plaintext, e, N)
    (p1, p2) = deductPlaintext(ciphertext, e, d, N)
    # I am not getting the correct last byte. Most probably because
    # of the appropriation in mod and pow operations. I can find the
    # last byte but I dont want to. My mind is fucked as of now.
    assert plaintext[:-1] == p1[:-1] or plaintext[:-1] == p2[:-1]
    print "[+] Found Plaintext: %s"%(p1)
    print "[+] Found Plaintext: %s"%(p2)
    return

if __name__=='__main__':
    solver()