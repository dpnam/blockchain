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

# User login and query account
old_user = dAppUser()
old_user.login(user_id='CUS00001', password='CUS00001')

print(f'User CUS00001:')
print(f'> Detail Amount: {old_user.query_amount_detail()}')
print(f'> Total Amount: {old_user.query_amount_available()}')
print(f'> History Transaction: {old_user.query_history_tx()}')

# Create 1 new user + random amount: 1 account, 1 tx
new_user = server.user_register(id_user='CUS00257', password='CUS00257', num_btc=23)
print('New User:')
print(new_user)

# Sample +4 new users + random amount: 4 accounts, 4 tx
for i in range(258, 261, 1):
    i += 1
    id_user = f"CUS{i:05}"
    password = id_user
    num_btc = random.randrange(20, 100, step=1)
    server.user_register(id_user, password, num_btc)

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
    
# Server check tx valid
server.run_tx_valid()

# Server create new block
server.block_gen()

# Old user run Proof of Work in 5 minutes (demo 1 user)
pow_result = old_user.proof_of_work(deadline=60*5)
print(pow_result)

# Server close block
if pow_result != None:
    server.block_chain_add(pow_result)