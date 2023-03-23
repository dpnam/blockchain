from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.exceptions import InvalidSignature

import random
import hashlib
import base58
from datetime import datetime
import binascii
import json
import os
import glob
import pandas as pd

# PARAMS
# Params
curve = ec.SECP256R1()
signature_algorithm = ec.ECDSA(hashes.SHA256())

DATABASE_PATH = 'database'
ACCOUNT_PATH = f'{DATABASE_PATH}/accounts'
PUBLIC_PATH = f'{DATABASE_PATH}/public'

class dAppUser:
    def __init__(self):
        self.k_pow = 4
        self.db_account = None
        self.block_chain = None
        
        self.buffer_tx = None
        self.buffer_tx_data = None
        
        self.buffer_block = None
        
        self.is_login = False
        self.user_id = None
        self.my_user = None
        
    def update_data(self):
        if self.is_login == False:
            print('Please login account !!!')
            return None
        
        self.db_account = json.load(open(f'{PUBLIC_PATH}/accounts.json'))
        self.block_chain = json.load(open(f'{PUBLIC_PATH}/blocks.json'))
        
        self.buffer_tx = json.load(open(f'{PUBLIC_PATH}/buffer_tx.json'))
        self.buffer_tx_data = self.buffer_tx['data']
        
        self.buffer_block = json.load(open(f'{PUBLIC_PATH}/buffer_block.json'))
        
        self.my_user = json.load(open(f'{ACCOUNT_PATH}/{self.user_id}.json'))        

    def login(self, user_id, password):
        try:
            user = json.load(open(f'{ACCOUNT_PATH}/{user_id}.json'))
            hash_password = hashlib.sha256(password.encode('utf-8')).hexdigest()
            if hash_password == user['root']['password']:
                self.is_login = True
                self.user_id = user_id
                self.update_data()
            else: 
                print('UserID or Password is incorrect')
        except:
            print('UserID or Password is incorrect')
            pass
        
    def logout(self):
        self.my_user = None
        self.is_login = False
        
    def update_buffer_tx(self, buffer_tx_data):
        self.buffer_tx['data'] = buffer_tx_data
        with open(f'{PUBLIC_PATH}/buffer_tx.json', "w+") as file: 
            json.dump(self.buffer_tx, file)
        
    def query_amount_detail(self):
        self.update_data()
        
        my_amount = self.my_user['root']['amount']
        result = {}
        for type_btc, list_address_btc in my_amount.items():
            count_btc = len(list_address_btc)
            result.update({type_btc: count_btc})

        return result
    
    def calculate_amount(self, my_amount):
        result = 0
        for type_btc, list_address_btc in my_amount.items():
            count_btc = len(list_address_btc)
            result += int(type_btc[:-3])*count_btc

        return result
    
    def query_amount_available_offline(self, checkpoint=None):
        self.update_data()
        
        # load data
        address = self.my_user['root']['address']
        history = self.my_user['history']
        history = pd.DataFrame(history)
        history['amount'] = history['amount'].apply(self.calculate_amount)

        history = pd.DataFrame(history)

        if checkpoint != None:
            history = history[history['timestamp'] <= checkpoint]

        # calculate amount in
        amount_in = 0

        history_in = history[history['to'] == address]
        if len(history_in) != 0:
            amount_in = history_in['amount'].sum()

        # calculate amount out
        amount_out = 0
        history_out = history[history['from'] == address]
        if len(history_out) != 0:
            amount_out = history_out['amount'].sum()

        # calculate amount availabel
        amount_available = amount_in - amount_out

        # return
        return amount_available
    
    def query_amount_available_online(self, address, checkpoint=None):
        self.update_data()
        
        # parms
        tx_total = []
        for name_block in self.block_chain.keys():
            block = self.block_chain[name_block]
            tx_total += block['data']

        tx_total += self.buffer_tx_data

        history = pd.DataFrame(tx_total)
        history['amount'] = history['amount'].apply(self.calculate_amount)
        history = pd.DataFrame(history)
        
        if checkpoint != None:
            history = history[history['timestamp'] <= checkpoint]

        # calculate amount in
        amount_in = 0
        if address == self.db_account['SER00000']['address']:
            amount_in = 100000

        history_in = history[history['to'] == address]
        if len(history_in) != 0:
            amount_in = history_in['amount'].sum()

        # calculate amount out
        amount_out = 0
        history_out = history[history['from'] == address]
        if len(history_out) != 0:
            amount_out = history_out['amount'].sum()

        # calculate amount availabel
        amount_available = amount_in - amount_out

        # return
        return amount_available
    
    def query_amount_available(self, checkpoint=None):
        return self.query_amount_available_offline(checkpoint)
    
    def query_history_tx(self):
        self.update_data()
        
        # load data
        id_user = self.my_user['id_user']
        history = pd.DataFrame(self.my_user['history'])

        dabase_account = pd.DataFrame(self.db_account).transpose().reset_index()
        dabase_account = dabase_account.rename(columns={'index': 'user_id'})
        dabase_account = dabase_account[['user_id', 'address']].drop_duplicates()

        # map with history
        history = history.merge(
            dabase_account.rename(columns={'address': 'from'}), 
            how='left', on='from'
        )
        history['from'] = history['user_id']
        history = history.drop(columns=['user_id'])

        history = history.merge(
            dabase_account.rename(columns={'address': 'to'}), 
            how='left', on='to'
        )
        history['to'] = history['user_id']
        history = history.drop(columns=['user_id'])

        # get history
        result = []
        history = history.sort_values(by=['timestamp'], ascending=True)
        for index, row in history.iterrows():
            timestamp = row['timestamp']
            from_user = row['from']
            to_user = row['to']
            amount_btc = self.calculate_amount(row['amount'])
            message = row['message']

            amount_balance = self.query_amount_available_offline(timestamp)

            if to_user == id_user:
                info = f"{timestamp}: Receive Money from {from_user} with {amount_btc} BTC. Message: '{message}'. Amount Available: {amount_balance} BTC"
            elif from_user == id_user:
                info = f"{timestamp}: Transfer Money to {to_user} with {amount_btc} BTC. Message: '{message}'. Amount Available: {amount_balance} BTC"

            result += [info]

        return result

    def account_find(self, address='164qjko1sVX1fAr5gzrphEHJu7NEXDUHhb'):
        self.update_data()
        
        for id_user, info in self.db_account.items():
            if info['address'] == address:
                return info
        return None
    
    def amount_atm(self, my_amount, withdrawals=50):
        # check enough money
        if self.calculate_amount(my_amount) < withdrawals:
            return None

        in_count_1_btc = len(my_amount['1 BTC'])
        in_count_2_btc = len(my_amount['2 BTC'])
        in_count_5_btc = len(my_amount['5 BTC'])
        in_count_10_btc = len(my_amount['10 BTC'])

        out_count_1_btc = 0
        out_count_2_btc = 0
        out_count_5_btc = 0
        out_count_10_btc = 0

        # round 1
        if (in_count_10_btc !=0) & (withdrawals != 0):
            out_count_10_btc = min(in_count_10_btc, int(withdrawals/10))
            withdrawals = withdrawals - out_count_10_btc*10

        if (in_count_5_btc !=0) & (withdrawals != 0):
            out_count_5_btc = min(in_count_5_btc, int(withdrawals/5))
            withdrawals = withdrawals - out_count_5_btc*5

        if (in_count_2_btc !=0) & (withdrawals != 0):
            out_count_2_btc = min(in_count_2_btc, int(withdrawals/2))
            withdrawals = withdrawals - out_count_2_btc*2

        if (in_count_1_btc !=0) & (withdrawals != 0):
            out_count_1_btc = min(in_count_1_btc, int(withdrawals/1))
            withdrawals = withdrawals - out_count_1_btc*1

        # round 2
        if (in_count_10_btc !=0) & (withdrawals != 0):
            out_count_10_btc += 1
            withdrawals = 0

        if (in_count_5_btc !=0) & (withdrawals != 0):
            out_count_5_btc += 1
            withdrawals = 0

        if (in_count_2_btc !=0) & (withdrawals != 0):
            out_count_2_btc += 1
            withdrawals = 0

        if (in_count_1_btc !=0) & (withdrawals != 0):
            out_count_1_btc += 1
            withdrawals = 0

        # result
        stast_result = {'1 BTC': out_count_1_btc, 
                        '2 BTC': out_count_2_btc, 
                        '5 BTC': out_count_5_btc,
                        '10 BTC': out_count_10_btc}
        in_result = {}
        out_result = {}
        for type_btc, count_btc in stast_result.items():
            in_list_address = my_amount[type_btc]
            out_list_address = []
            if count_btc != 0:
                out_list_address = my_amount[type_btc][:count_btc]
                in_list_address = my_amount[type_btc][count_btc+1:]

            in_result[type_btc] = in_list_address
            out_result[type_btc] = out_list_address

        # return 
        return in_result, out_result
    
    def tx_gen(self, 
               to_add='1QBgVdUdMChYa64o7mx8eA4ycNySU6owzb',
               deposits=10, 
               message='Init account for customer: ADD00001',
               fee=0):

        self.update_data() 
        
        # info user
        owner_amount = self.my_user['root']['amount']
        from_add = self.my_user['root']['address']
        private_key = self.my_user['root']['private_key']
        
        # check enough money
        if self.calculate_amount(owner_amount) < deposits:
            print('Not Enough BTC')
            return None
        
        # amount_atm
        remain_amount, transfer_amount = self.amount_atm(owner_amount, deposits)

        # time
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S:%f')
        
        # sign
        info = f'{from_add}{to_add}{str(transfer_amount)}{message}{timestamp}'
        private_key_object = ec.derive_private_key(int(private_key, 16), curve, default_backend())

        signature = private_key_object.sign(info.encode('utf-8'), signature_algorithm).hex()

        # hash
        info = f'{info}{signature}'
        hash_tx = hashlib.sha256(bytearray(info.encode('utf-8'))).hexdigest()

        # fee
        fee = fee

        # tx
        tx = {'from': from_add, 'to': to_add, 'amount': transfer_amount, 'message': message, 
              'signature': signature, 'hash': hash_tx, 'timestamp': timestamp}
        
        buffer_tx_data = self.buffer_tx_data + [tx]
        self.update_buffer_tx(buffer_tx_data)

    def tx_valid(self, tx):
        self.update_data()
        
        # get info
        from_add = tx['from']
        to_add = tx['to']
        transfer_amount = tx['amount']
        signature = bytes(bytearray.fromhex(tx['signature']))
        message = tx['message']
        timestamp = tx['timestamp']

        # verify: sum(in_tx) - sum(out_tx) - free >= 0
        deposits = self.calculate_amount(transfer_amount)

        if self.query_amount_available_online(from_add, timestamp) < deposits:
            print('Not Enough BTC')
            return None

        # verify: signarute
        info = f'{from_add}{to_add}{str(transfer_amount)}{message}{timestamp}'
        from_account = self.account_find(from_add)
        if from_account == None: return False

        public_key = bytes(bytearray.fromhex(from_account['public_key']))
        public_key_object = ec.EllipticCurvePublicKey.from_encoded_point(curve, public_key)

        try:
            public_key_object.verify(signature, info.encode('utf-8'), signature_algorithm)
            return True
        except InvalidSignature:
            return False
        
    def proof_of_work(self, deadline=60*2):
        self.update_data()
        block = self.buffer_block
        if len(block) == 0:
            return None
        
        name_block = list(block.keys())[0]
        data_block = block[name_block]
        
        # start minner
        start = datetime.now()
        # max_values = 2**(256-self.k_pow*8)
        pattern = ''.join(['0' for i in range(0, self.k_pow, 1)])

        # info
        previous_hash_block = data_block['previous_hash_block']
        merkel_root = data_block['merkel_root']
        timestamp = data_block['timestamp']
        info = f'{previous_hash_block}{merkel_root}{timestamp}'

        # run
        nonce = random.randint(1000, 100000)
        while True:
            # generate nonce
            nonce += 1
            info = f'{info}{nonce}'
            hash_block = hashlib.sha256(info.encode()).hexdigest()

            # match pattern
            if hash_block.startswith(pattern):
                row = {'hash': hash_block, 'nonce': nonce}
                return row

            # time out
            cur = datetime.now()
            delta_time = (cur-start)
            if delta_time.seconds > deadline:
                return None