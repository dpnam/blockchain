import re
import random
import math
import collections
from utils import generate_prime, EC, ECC

# init ECC
p = generate_prime(n=160)
a = random.getrandbits(128) % p
b = random.getrandbits(128) % p
ecc = ECC(a, b, p)

# Test: Elliptic Diffie-Hellman key exchange
share_secret_key = ecc.key_exchange(n_a=12, n_b=87)
print(share_secret_key)

# Test: Elliptic ElGamal public key cryptography
private_key = '0x12'
ephemeral_key = 11
private_key, public_key = ecc.el_gamal_keys(private_key)
print('Private Key: ' + private_key)
print('Public Key: ' + public_key)

msg = "Dang Phuong Nam truong Dai hoc Khoa hoc Tu nhien TP.HCM - Mon: Phan Tich Chuoi Khoi " 

ciphertext_1_s, ciphertext_2_s = ecc.encrypt_ecc_msg(msg, public_key, ephemeral_key)
print('Ciphertext 1: ' + ciphertext_1_s)
print('Ciphertext 2: ' + ciphertext_2_s)


decrypt_text = ecc.decrypt_ecc_msg(ciphertext_1_s, ciphertext_2_s, private_key)
print('Decrypt Text: ' + decrypt_text)