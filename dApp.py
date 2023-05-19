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

class dAppInit:
    def __init__(self, num_customer=2**8):
        # default
        self.k_pow = 4
        self.block_size = 64
        
        # init btc in network
        distribute_btc = {
            '1 BTC': 45000,
            '2 BTC': 10000,
            '5 BTC': 5000,
            '10 BTC': 1000,
        }
        self.total_btc = {}
        for type_money, count_money in distribute_btc.items():
            list_address_btc = []
            for i in range(0, count_money, 1):
                timestamp_btc = datetime.now().strftime('%Y-%m-%d %H:%M:%S:%f')
                info_btc = f'{type_money}{i}{timestamp_btc}'
                hash_info_btc = hashlib.sha256(info_btc.encode('utf-8')).hexdigest()
                address_btc = base58.b58encode(bytearray.fromhex(hash_info_btc)).decode('utf-8')
                list_address_btc += [address_btc]
                
            row = {type_money: list_address_btc}
            self.total_btc.update(row)
        
        # assign params
        self.num_customer = num_customer
        self.server = None
        self.db_account = {}
        self.block_chain = {}
        
    def add_gen(self, public_key):
        sha256 = hashlib.sha256(bytearray.fromhex(public_key)).hexdigest()
        ripemd160 = '00' + hashlib.new('ripemd160', bytearray.fromhex(sha256)).hexdigest()

        sha_1 = hashlib.sha256(bytearray.fromhex(ripemd160)).hexdigest()
        sha_2 = hashlib.sha256(bytearray.fromhex(sha_1)).hexdigest()
        checksum = sha_2[:8]

        address = base58.b58encode(bytearray.fromhex(ripemd160 + checksum)).decode('utf-8')

        return address
    
    def account_gen(self, id_user='CUS0001', password='CUS0001'):
        # Check exist account
        if len(self.db_account) > 0:
            if id_user in list(self.db_account.keys()):
                print(f"User '{id_user}': already exists in the database, Please try again with new user!")
                return None

        # Create Acount
        ## timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S:%f')

        ## private key and public key
        private_key_object = ec.generate_private_key(curve)
        public_key_object = private_key_object.public_key()
        private_key = hex(private_key_object.private_numbers().private_value)[2:]
        public_key = public_key_object.public_bytes(serialization.Encoding.X962, 
                                                     serialization.PublicFormat.UncompressedPoint).hex()

        ## address
        address = self.add_gen(public_key)
        
        ## hash password
        hash_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        ## info account
        account = {'id_user': id_user,
                   'root': {
                       'password': hash_password,
                       'private_key': private_key, 
                       'public_key': public_key, 
                       'address': address,
                       'amount': {
                           '1 BTC': [],
                           '2 BTC': [],
                           '5 BTC': [],
                           '10 BTC': [],
                       },
                       'timestamp': timestamp
                   },
                   'history': []
                  }

        # Update database account
        self.db_account.update({
            id_user: {
                'public_key': public_key, 
                'address': address
            }
        })

        return account
    
    def amount_available(self, my_amount):
        result = 0
        for type_btc, list_address_btc in my_amount.items():
            count_btc = len(list_address_btc)
            result += int(type_btc[:-3])*count_btc

        return result
    
    def amount_atm(self, my_amount, withdrawals=50):
        # check enough money
        if self.amount_available(my_amount) < withdrawals:
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
               user,
               to_add='1QBgVdUdMChYa64o7mx8eA4ycNySU6owzb',
               deposits=10, 
               private_key='6cdd8b34fdc6b39ecdd1326fd0e60fce1642e18ccfb99fbec611f1539aa1c0fe',
               message='Init account for customer: ADD00001',
               fee=0):

        # info user
        owner_amount = user['root']['amount']
        from_add = user['root']['address']
        
        # check enough money
        if self.amount_available(owner_amount) < deposits:
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
        
        # update user
        user['root']['amount'] = remain_amount

        # return
        return user, tx
    
    def amount_gen(self, id_user, deposits=10):
        # get info
        from_add = self.server['root']['address']
        private_key = self.server['root']['private_key']
        to_add = self.db_account[id_user]['address']
        message = f'Init account for customer: {id_user}'
        fee = deposits*1/10000

        self.server, tx = self.tx_gen(self.server, to_add, deposits, private_key, message, fee)
        
        return tx
    
    def account_find(self, address='164qjko1sVX1fAr5gzrphEHJu7NEXDUHhb'):
        for id_user, info in self.db_account.items():
            if info['address'] == address:
                return info
        return None
    
    def tx_valid(self, tx):
        # get info
        from_add = tx['from']
        to_add = tx['to']
        transfer_amount = tx['amount']
        signature = bytes(bytearray.fromhex(tx['signature']))
        message = tx['message']
        timestamp = tx['timestamp']

        # check exist

        # verify: double spend

        # verify: sum(in_tx) - sum(out_tx) - free >= 0

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
        
    def block_gen(self, tx_list_sub, name_block='BLK0000000001', name_type='init'):
        # create time
        create_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S:%f')

        # merkel tree
        hash_list = [tx['hash'] for tx in tx_list_sub]
        while len(hash_list) != 1:
            buffer_hash_list = []
            for i in range(0, len(hash_list), 2):
                info = f'{hash_list[i]}{hash_list[i+1]}'
                hash_nodes = hashlib.sha256(bytearray(info.encode('utf-8'))).hexdigest()
                buffer_hash_list += [hash_nodes]

            hash_list = buffer_hash_list

        merkel_root = hash_list[0]

        # timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S:%f')

        # previous hash block
        previous_hash_block = None
        if name_type == 'append':
            previous_hash_block = list(self.block_chain.values())[-1]['hash']

        # return
        row = {'name_block': name_block, 'previous_hash_block': previous_hash_block, 
               'merkel_root': merkel_root, 'timestamp':timestamp}
        return row

    def proof_of_work(self, block_gen, deadline=60*2):
        # start minner
        start = datetime.now()
        # max_values = 2**(256-self.k_pow*8)
        pattern = ''.join(['0' for i in range(0, self.k_pow, 1)])

        # info
        previous_hash_block = block_gen['previous_hash_block']
        merkel_root = block_gen['merkel_root']
        timestamp = block_gen['timestamp']
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
            
    def history_update(self, account, tx):
        history = account['history']
        history += [tx]
        account['history'] = history
        return account
    
    def amount_update(self, account, amount):
        account['root']['amount'] = amount
        return account
        
    def run(self):
        # init: server and user_list
        self.server = self.account_gen('SER00000', 'SER00000')
        self.server['root']['amount'] = self.total_btc
        
        user_list = []
        for i in range(0, self.num_customer, 1):
            i += 1
            id_user = f"CUS{i:05}"
            password = id_user
            user = self.account_gen(id_user, password)
            user_list += [user]
        
        # init: tx_list
        tx_list = []
        for user in user_list:
            deposits = random.randrange(20, 100, step=1)
            tx = self.amount_gen(user['id_user'], deposits)
            if self.tx_valid(tx): tx_list += [tx]
            
        # block: collect and save
        block_index = 1
        for i in range(0, len(tx_list), self.block_size):
            # get transaction
            tx_list_sub = tx_list[i:i+self.block_size] 

            # block gen
            name_block = f"BLK{block_index:010}"
            block_gen = self.block_gen(tx_list_sub, name_block)

            # proof of work
            pow_result = self.proof_of_work(block_gen, deadline=60*5)

            if pow_result == None: 
                print(f'#{i} Fail')
                break
            else:
                print(f'#{i} True')

            # block
            data_block = {
                'timestamp': block_gen['timestamp'],
                'previous_hash_block': block_gen['previous_hash_block'],
                'merkel_root': block_gen['merkel_root'],
                'nonce': pow_result['nonce'],
                'hash': pow_result['hash'],
                'transaction_count': len(tx_list_sub),
                'data': tx_list_sub
            }
            block = {block_gen['name_block']: data_block}

            # update chain
            self.block_chain.update(block)
            block_index += 1
    
            # update history of server
            for tx in data_block['data']:
                tx.update({'name_block': name_block})
                
                # update server
                self.server = self.history_update(self.server, tx)
                
                # update user
                index_user = None
                for index in range(0, len(user_list), 1):
                    user = user_list[index]
                    if user['root']['address'] == tx['to']:
                        index_user = index
                        break
                
                user = user_list[index]
                user = self.history_update(user, tx)
                user = self.amount_update(user, tx['amount'])
                user_list[index] = user

        # save database
        clean_public_file = [os.remove(file) for file in glob.glob(f'{PUBLIC_PATH}/*')]
        clean_account_file = [os.remove(file) for file in glob.glob(f'{ACCOUNT_PATH}/*')]
        
        with open(f'{ACCOUNT_PATH}/SER00000.json', "w+") as file: 
            json.dump(self.server, file)
            
        with open(f'{PUBLIC_PATH}/accounts.json', "w+") as file:
            json.dump(self.db_account, file)
            
        with open(f'{PUBLIC_PATH}/blocks.json', "w+") as file: 
            json.dump(self.block_chain, file)
            
        for user in user_list:
            id_user= user['id_user']
            with open(f'{ACCOUNT_PATH}/{id_user}.json', "w+") as file: 
                json.dump(user, file)
    
    pass

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

        # check exist
        from_account = self.account_find(from_add)
        if from_account == None: return False
        
        to_account = self.account_find(to_add)
        if to_account == None: return False
        
        # verify: sum(in_tx) - sum(out_tx) - free >= 0
        deposits = self.calculate_amount(transfer_amount)

        if self.query_amount_available_online(from_add, timestamp) < deposits:
            print('Not Enough BTC')
            return None

        # verify: signarute
        info = f'{from_add}{to_add}{str(transfer_amount)}{message}{timestamp}'
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
            
    pass

class dAppServer:
    def __init__(self):
        self.k_pow = 4
        self.block_size = 64
        
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
            if user_id != 'SER00000':
                print('UserID or Password is incorrect')

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
        if self.buffer_tx['timestamp'] == None:
            self.buffer_tx['timestamp'] = datetime.now().strftime('%Y-%m-%d %H:%M:%S:%f')
            
        self.buffer_tx['data'] = buffer_tx_data
        with open(f'{PUBLIC_PATH}/buffer_tx.json', "w+") as file: 
            json.dump(self.buffer_tx, file)
            
    def init_buffer_tx(self):
        buffer_tx = {
            'timestamp': None,
            'data': []
        }
        with open(f'{PUBLIC_PATH}/buffer_tx.json', "w+") as file: 
            json.dump(buffer_tx, file)

    def init_buffer_block(self):
        buffer_block = {}
        with open(f'{PUBLIC_PATH}/buffer_block.json', "w+") as file: 
            json.dump(buffer_block, file)
        
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

            amount_balance = self.query_amount_available_from_account(timestamp)

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
    
    def add_gen(self, public_key):
        sha256 = hashlib.sha256(bytearray.fromhex(public_key)).hexdigest()
        ripemd160 = '00' + hashlib.new('ripemd160', bytearray.fromhex(sha256)).hexdigest()

        sha_1 = hashlib.sha256(bytearray.fromhex(ripemd160)).hexdigest()
        sha_2 = hashlib.sha256(bytearray.fromhex(sha_1)).hexdigest()
        checksum = sha_2[:8]

        address = base58.b58encode(bytearray.fromhex(ripemd160 + checksum)).decode('utf-8')

        return address

    def account_gen(self, id_user='CUS0001', password='CUS0001'):
        self.update_data()
        
        # Check exist account
        if len(self.db_account) > 0:
            if id_user in list(self.db_account.keys()):
                print(f"User '{id_user}': already exists in the database, Please try again with new user!")
                return None

        # Create Acount
        ## timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S:%f')

        ## private key and public key
        private_key_object = ec.generate_private_key(curve)
        public_key_object = private_key_object.public_key()
        private_key = hex(private_key_object.private_numbers().private_value)[2:]
        public_key = public_key_object.public_bytes(serialization.Encoding.X962, 
                                                    serialization.PublicFormat.UncompressedPoint).hex()

        ## address
        address = self.add_gen(public_key)

        ## hash password
        hash_password = hashlib.sha256(password.encode('utf-8')).hexdigest()

        ## info account
        account = {'id_user': id_user,
                   'root': {
                       'password': hash_password,
                       'private_key': private_key, 
                       'public_key': public_key, 
                       'address': address,
                       'amount': {
                           '1 BTC': [],
                           '2 BTC': [],
                           '5 BTC': [],
                           '10 BTC': [],
                       },
                       'timestamp': timestamp
                   },
                   'history': []
                  }
        
        # Update database account
        self.db_account.update({
            id_user: {
                'public_key': public_key, 
                'address': address
            }
        })
        with open(f'{PUBLIC_PATH}/accounts.json', "w+") as file:
            json.dump(self.db_account, file)

        # return
        with open(f'{ACCOUNT_PATH}/{id_user}.json', "w+") as file: 
            json.dump(account, file)
        
        return account

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
    
    def user_register(self, id_user='CUS0001', password='CUS0001', num_btc=30):
        self.update_data()
        
        user = self.account_gen(id_user, password)

        if user == None:
            return None

        # get info
        from_add = self.my_user['root']['address']
        private_key = self.my_user['root']['private_key']
        to_add = self.db_account[id_user]['address']
        message = f'Init account for customer: {id_user}'
        fee = num_btc*1/10000

        self.tx_gen(to_add, num_btc, message, fee)
        
        return user
    
    def tx_valid(self, tx):
        self.update_data()
        
        # get info
        from_add = tx['from']
        to_add = tx['to']
        transfer_amount = tx['amount']
        signature = bytes(bytearray.fromhex(tx['signature']))
        message = tx['message']
        timestamp = tx['timestamp']
        
        # check exist
        from_account = self.account_find(from_add)
        if from_account == None: return False
        
        to_account = self.account_find(to_add)
        if to_account == None: return False

        # verify: sum(in_tx) - sum(out_tx) - free >= 0
        deposits = self.calculate_amount(transfer_amount)
        if self.query_amount_available_online(from_add, timestamp) < deposits:
            print('Not Enough BTC')
            return None

        # verify: signarute
        info = f'{from_add}{to_add}{str(transfer_amount)}{message}{timestamp}'
        public_key = bytes(bytearray.fromhex(from_account['public_key']))
        public_key_object = ec.EllipticCurvePublicKey.from_encoded_point(curve, public_key)

        try:
            public_key_object.verify(signature, info.encode('utf-8'), signature_algorithm)
            return True
        except InvalidSignature:
            return False
        
    def run_tx_valid(self):
        self.update_data()
        
        # check tx_valid
        buffer_tx_data_valid = []
        for tx in self.buffer_tx_data:
            if self.tx_valid(tx):
                buffer_tx_data_valid += [tx]
                
        # update data
        if len(buffer_tx_data_valid) == 0:
            self.init_buffer_block()
        else:
            self.update_buffer_tx(buffer_tx_data_valid)
        
    def block_gen(self):
        self.update_data()
        index_block = int(list(self.block_chain.keys())[-1][-10:]) + 1
        name_block = f"BLK{index_block:010}"
        
        # enough tx?
        if len(self.buffer_tx_data) < self.block_size:
            return None
        
        # get data
        tx_list_sub = self.buffer_tx_data[:self.block_size]
        buffer_tx_data = self.buffer_tx_data[self.block_size+1:]
        
        # update data
        if len(buffer_tx_data) == 0:
            self.init_buffer_tx()
        else:
            self.update_buffer_tx(buffer_tx_data)
        
        # create time
        create_time = datetime.now().strftime('%Y-%m-%d %H:%M:%S:%f')

        # merkel tree
        hash_list = [tx['hash'] for tx in tx_list_sub]
        while len(hash_list) != 1:
            buffer_hash_list = []
            for i in range(0, len(hash_list), 2):
                info = f'{hash_list[i]}{hash_list[i+1]}'
                hash_nodes = hashlib.sha256(bytearray(info.encode('utf-8'))).hexdigest()
                buffer_hash_list += [hash_nodes]

            hash_list = buffer_hash_list

        merkel_root = hash_list[0]

        # timestamp
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S:%f')

        # previous hash block
        previous_hash_block = None
        previous_hash_block = list(self.block_chain.values())[-1]['hash']

        
        # add name_block in tx
        for i in range(0, len(tx_list_sub), 1):
            tx = tx_list_sub[i]
            tx.update({'name_block': name_block})
            tx_list_sub[i] = tx
        
        # return
        data_block = {
                'timestamp': timestamp,
                'previous_hash_block': previous_hash_block,
                'merkel_root': merkel_root,
                'nonce': None,
                'hash': None,
                'transaction_count': len(tx_list_sub),
                'data': tx_list_sub
            }
        block = {name_block: data_block}

        with open(f'{PUBLIC_PATH}/buffer_block.json', "w+") as file: 
            json.dump(block, file)
        
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
            
    def update_user(self, address, tx, type_address='from'):
        self.update_data()
        
        user_id = None
        for cur_user_id, info in self.db_account.items():
            if info['address'] == address:
                user_id = cur_user_id
        
        user = json.load(open(f'{ACCOUNT_PATH}/{user_id}.json'))
        history = user['history']
        history += [tx]
        user['history'] = history
        
        amount = user['root']['amount']
        if type_address == 'from':
            transfer_amount = tx['amount']
            
            for type_btc, count_btc in transfer_amount.items():
                in_btc_address = amount[type_btc]
                tx_btc_address = transfer_amount[type_btc]
                
                out_btc_address = list(set(in_btc_address) - set(tx_btc_address))
                amount[type_btc] = out_btc_address
                
        elif type_address == 'to':
            receive_amount = tx['amount']
            
            for type_btc, count_btc in receive_amount.items():
                in_btc_address = amount[type_btc]
                tx_btc_address = receive_amount[type_btc]
                
                out_btc_address = list(set(in_btc_address) | set(tx_btc_address))
                amount[type_btc] = out_btc_address
                
        user['root']['amount'] = amount
        
        with open(f'{ACCOUNT_PATH}/{user_id}.json', "w+") as file: 
            json.dump(user, file)
            
    def block_chain_add(self, pow_result):
        self.update_data()
        block = self.buffer_block

        if (len(block) == 0) or (pow_result == None):
            return None
        
        # update nonce and hash
        name_block = list(block.keys())[0]
        data_block = block[name_block]
        
        data_block.update({'nonce': pow_result['nonce']})
        data_block.update({'hash': pow_result['hash']})
        
        block = {name_block: data_block}
        
        # update chain
        self.block_chain.update(block)
        with open(f'{PUBLIC_PATH}/blocks.json', "w+") as file: 
            json.dump(self.block_chain, file)

        # update history of server
        for tx in data_block['data']:
            tx.update({'name_block': name_block})
            
            address_from = tx['from']
            self.update_user(address_from, tx, type_address='from')
            
            address_to = tx['to']
            self.update_user(address_to, tx, type_address='to')
            
        # init buffer block
        self.init_buffer_block()
    
    pass