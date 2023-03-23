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
        self.server = self.account_gen('SER00000')
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

if __name__ == "__main__":
    dAppInit(num_customer=2**8).run()