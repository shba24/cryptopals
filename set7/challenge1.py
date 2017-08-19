"""
Main Code.
"""
import os
import sys
from crypty import a2h, h2a, generate_key, pad_pkcs_7, unpad_pkcs_7,xor_ascii_strings
from crypty.ciphers import cbc as aes_cbc

key = generate_key()

def cbc_mac(message, key, iv):
    message = pad_pkcs_7(a2h(message))
    ciphertext = h2a(aes_cbc.infra.encrypt_manual(message, key, iv))
    return ciphertext[-16:]

def verify_mac(message):
    msg = message[:-32]
    iv = a2h(message[-32:-16])
    mac = message[-16:]
    if mac != cbc_mac(msg, key, iv):
        return False
    else:
        return True
    return False

def generate_message(sender, recept, amount):
    iv = generate_key()
    message = "from=%s&to=%s&amount=%d"%(sender, recept, amount)
    final_message = message + h2a(iv) + cbc_mac(message, key, iv)
    return final_message

def solver1():
    message = generate_message("shubbans", "hardik", 1000)
    if verify_mac(message):
        print "[+] MAC Verified."
    else:
        print "[-] MAC not Verified."
    msg = message[:-32]
    iv = message[-32:-16]
    mac = message[-16:]
    mal_msg = msg[:5] + "dnbansal" + msg[13:]
    mal_iv = h2a(xor_ascii_strings(h2a(xor_ascii_strings(iv, msg[:16])), mal_msg[:16]))
    mal_mac = mac
    if verify_mac(mal_msg+mal_iv+mal_mac):
        print "[+] MAC Verified."
    else:
        print "[-] MAC not Verified."
    return

key2 = generate_key()
iv2 = a2h(b"\x00"*16)

def verify_mac1(message):
    msg = message[:-16]
    mac = message[-16:]
    if mac != cbc_mac(msg, key2, iv2):
        return False
    else:
        return True
    return False

def solver2():
    global key2
    global iv2
    tuples = [[b'Bob', b'5'], [b'Charlie', b'10']]
    sender = b'Alice'
    recipients = b';'.join([t[0] + b':' + str(int(t[1])).encode('ascii') for t in tuples])
    message = b'from=' + sender + b'&tx_list=' + recipients
    final_message = message + cbc_mac(message, key2, iv2)
    msg = final_message[:-16]
    mac_1 = final_message[-16:]
    tuples_1 = [[b'M', b'0'], [b'Mallory', b'1000000']]
    sender_1 = b'M'
    recipients_1 = b';'.join([t[0] + b':' + str(int(t[1])).encode('ascii') for t in tuples_1])
    message_1 = b'from=' + sender_1 + b'&tx_list=' + recipients_1
    final_message_1 = message_1 + cbc_mac(message_1, key2, iv2)
    mal_message = h2a(pad_pkcs_7(a2h(msg))) + h2a(xor_ascii_strings(mac_1, final_message_1[:16])) + final_message_1[16:]
    if verify_mac1(mal_message):
        print "[+] MAC Verified."
    else:
        print "[-] MAC not Verified."
    return

if __name__=='__main__':
    solver1()
    solver2()