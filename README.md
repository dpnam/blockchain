# Blockchain
## Lab 01: ECC Libs
**File: demo_lab01.py**
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
## Lab 02: dApp
**File: demo_lab02.py**
```
import random
import json
import pandas as pd
from dApp import dAppInit, dAppUser, dAppServer

DATABASE_PATH = 'database'
PUBLIC_PATH = f'{DATABASE_PATH}/public'

# Init Block: 256 user + 1 server
dAppInit.run()

# Server login
server = dAppServer()
server.login(user_id='SER00000', password='SER00000')
```
**User login and query account:**
```
# code
old_user = dAppUser()
old_user.login(user_id='CUS00001', password='CUS00001')

print(f'User CUS00001:')
print(f'> Detail Amount: {old_user.query_amount_detail()}')
print(f'> Total Amount: {old_user.query_amount_available()}')
print(f'> History Transaction: \n {old_user.query_history_tx()}')

# output
User CUS00001:
> Detail Amount: {'1 BTC': 1, '2 BTC': 0, '5 BTC': 0, '10 BTC': 2}
> Total Amount: 21
> History Transaction:
["2023-03-21 23:08:38:805398: Receive Money from SER00000 with 21 BTC. Message: 'Init account for customer: CUS00001'. Amount Available: 21 BTC"]
```
**Create new account:**
```
# code
new_user = server.user_register(id_user='CUS00257', password='CUS00257', num_btc=23)
print('New User:')
print(new_user)

# ouput
New User:
{'id_user': 'CUS00257',
 'root': {'password': '0157b5b38113e7a861d44555766de071115741c9f19e90bdcdbf1a2e1d5918f9',
  'private_key': '247f26821ccc89b9f6ab8aad5ce812b6c55a0e6557501d175870512eec6906db',
  'public_key': '047a4e9c293674a4b54f32e77a5a5a568be8aa711ffc52e2b14b9ec2e0a902c3fed67390eabbcdb5ee77a2a248470d5f230fdae8f31a8cfa14c6baec02a2406851',
  'address': '1CZKAGz6XwGnN2vY4xsbTito9mbyTeCjJz',
  'amount': {'1 BTC': [], '2 BTC': [], '5 BTC': [], '10 BTC': []},
  'timestamp': '2023-03-24 21:20:43:569011'},
 'history': []}
```

```
# Sample +4 new users + random amount: 4 accounts, 4 tx
for i in range(258, 261, 1):
    i += 1
    id_user = f"CUS{i:05}"
    password = id_user
    num_btc = random.randrange(20, 100, step=1)
    server.user_register(id_user, password, num_btc)
```
**Sample Transaction: 64 tx for 1 block:**
```
# Old user stranfer to new user 10 BTC
old_user.tx_gen(to_add='1CZKAGz6XwGnN2vY4xsbTito9mbyTeCjJz', 
                deposits=10, message='Charge to buy laptop', fee=0)

# Sample + 60tx random => 1 block: 64 tx
db_account = json.load(open(f'{PUBLIC_PATH}/accounts.json'))
total_account_df = pd.DataFrame(db_account).T.reset_index().rename(columns={'index': 'User'})
total_account_df = total_account_df[total_account_df['User'] != 'SER00000']
sample_address = total_account_df.sample(60)['address'].tolist()

for address in sample_address:
    server.tx_gen(to_add=address,deposits=random.randrange(1, 10, step=1), 
                  message='Charge sample', fee=0)
```
**Server collect tx to create new block:**
```
# Server check tx valid
server.run_tx_valid()

# Server create new block
server.block_gen()
```
**Demo 1 user run Proof of Work:**
```
# code
pow_result = old_user.proof_of_work(deadline=60*5)
print(pow_result)

# output:
{'hash': '0000df41722d7ce1f3b7ac04a4eb303e36547bc7480e7d256b2d56c733c376ac',
 'nonce': 157737}
```
**Add bloc and save data:**
```
if pow_result != None:
    server.block_chain_add(pow_result)
```