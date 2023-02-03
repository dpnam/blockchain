import random
import math
import collections
from ecc import generate_prime, EC, ECC

# init ECC
p = generate_prime(n=160)
a = random.getrandbits(128) % p
b = random.getrandbits(128) % p
ecc = ECC(a, b, p)
print('Elliptic Curve: ')
print(f'>> a = {a}')
print(f'>> b = {b}')
print(f'>> p = {p}')
print(f'>> P: ({ecc.P.x}, {ecc.P.y})')

# Test: Elliptic Diffie-Hellman key exchange
share_secret_key = ecc.key_exchange(n_a=12, n_b=87)
print('\n')
print('Demo Key Exchange:')
print('>> Share Secret Key: ' + share_secret_key)

# Test: Elliptic ElGamal public key cryptography
private_key = '0x12'
ephemeral_key = 11
private_key, public_key = ecc.el_gamal_keys(private_key)

msg = "Dang Phuong Nam truong Dai hoc Khoa hoc Tu nhien TP.HCM - Mon: Phan Tich Chuoi Khoi " 
ciphertext_1_s, ciphertext_2_s = ecc.encrypt_ecc_msg(msg, public_key, ephemeral_key)
decrypt_msg = ecc.decrypt_ecc_msg(ciphertext_1_s, ciphertext_2_s, private_key)

print('\n')
print('Demo Elliptic ElGamal:')
print('>> Private Key: ' + private_key)
print('>> Public Key: ' + public_key)
print('>> Original Msg: ' + msg)
print('>> Encrypted Msg: ')
print('>>> Ciphertext 1: ' + ciphertext_1_s)
print('>>> Ciphertext 2: ' + ciphertext_2_s)
print('>> Decrypted Msg: ' + decrypt_msg)