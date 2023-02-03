# Blockchain
## Lab 01: ECC Libs
```
# import libs
import re
import random
import math
import collections
from ecc import generate_prime, EC, ECC

# init ECC
p = generate_prime(n=160)
a = random.getrandbits(128) % p
b = random.getrandbits(128) % p
ecc = ECC(a, b, p)
```

**Elliptic Curve:**
```
# code
print('Elliptic Curve: ')
print(f'>> a = {a}')
print(f'>> b = {b}')
print(f'>> p = {p}')
print(f'>> P: ({ecc.P.x}, {ecc.P.y})')

# output
Elliptic Curve: 
>> a = 234581104975382236878888768276223064130
>> b = 280166288875019025451456973086667544464
>> p = 61665514896003558213805204574229060578240203393
>> P: (48444901944785353932440061113214203530, 56380512268614344938483402324276588933033328120)
```

**Demo Key Exchange:**
```
# code
share_secret_key = ecc.key_exchange(n_a=12, n_b=87)
print('Demo Key Exchange:')
print('>> Share Secret Key: ' + share_secret_key)

# output
Demo Key Exchange:
>> Share Secret Key: 0x7b040f0b93c0b88ce9e3dc8dc60013ebf2cd5a954269ea8e7a0fdd3d652a3d73d6bfc24f763e166b
```

**Demo Elliptic ElGamal:**
```
# code
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

# ouput
Demo Elliptic ElGamal:
>> Private Key: 0x12
>> Public Key: 0x185765c3a101e68287f51684854f5bba7d9ea03477e873422c7d9adb72d6a80f49787fa540ee22ed
>> Original Msg: Dang Phuong Nam truong Dai hoc Khoa hoc Tu nhien TP.HCM - Mon: Phan Tich Chuoi Khoi 
>> Encrypted Msg: 
>>> Ciphertext 1: 0x9ba4883b9cc586d65f29396efb819b3cbc9e98ee1a337242a201e1ad332d7f1afbde6ab8048bfd269ba4883b9cc586d65f29396efb819b3cbc9e98ee1a337242a201e1ad332d7f1afbde6ab8048bfd269ba4883b9cc586d65f29396efb819b3cbc9e98ee1a337242a201e1ad332d7f1afbde6ab8048bfd269ba4883b9cc586d65f29396efb819b3cbc9e98ee1a337242a201e1ad332d7f1afbde6ab8048bfd269ba4883b9cc586d65f29396efb819b3cbc9e98ee1a337242a201e1ad332d7f1afbde6ab8048bfd26
>>> Ciphertext 2: 0x312133498a3e4040c896b5aff2a348237810a72c8e95985a2dbb823d1312593e98ebaed379b976a51783747bcff79f7986f2396c08e441bb4295e6a0030f0987d8d81c773abcdf93338a0280fd767e9ca0063bcd480fc6b4ff0dd343c801682ff375e3feaa50c1cfa34f697952db666381a9a7fef287edef055846e074f4d1c5b6d1348330a6ae6d1e9cace543fded69cda7483a1e2c660e316564fcf51e9cf21d91dcba36f7b7c03561d6f159b0bc919ef02f9b04c5238d6507d8c768eedc5b8f164c8ad45a2b8f
>> Decrypted Msg: Dang Phuong Nam truong Dai hoc Khoa hoc Tu nhien TP.HCM - Mon: Phan Tich Chuoi Khoi 
```