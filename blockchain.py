import binascii
from http.server import BaseHTTPRequestHandler
import hashlib
from inspect import signature
import json
from multiprocessing.sharedctypes import Value
import socketserver
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Hash import SHA256
import requests
from bitcoin import *
from time import time

from hashlib import sha256
#sha256("ABC".encode("ascii")).hexdigest()

from transaction import Transaction 
from block import Block

Customer = ""
NETWORK_FILE = "network.json"

def get_other_ports(customer):
    try:
        with open(NETWORK_FILE) as f:
            d = json.load(f)
    except IOError:
        print("network file does not exists")
        sys.exit()

    ports = []
    for key in d:
        if key != customer:
            data = d[key]
            ports.append(data["server_port"])

    return ports

def get_balance(customer):
    try:
        with open(NETWORK_FILE) as f:
            d = json.load(f)
    except IOError:
        print("network file does not exists")
        sys.exit()

    try:
        data = d[customer]
    except:
        print("customer data not found")
        sys.exit()

    return data["initial_balance"]

class Server(BaseHTTPRequestHandler):

    DIFFICULTY = 4
    
    PRIVATE_KEY_FILE = "private_key_file"
    PUBLIC_KEY_FILE = "public_key_file"

    chain = []
    unverified_transactions_string = []
    verified_transactions = []
    honey_list = []
    other_ports = []
    new_block_data = {}
    new_block = {}
    balance = 0

    genesis_block_created = False
    customer_set = False

    def __init__(self, request: bytes, client_address: tuple[str, int], server: socketserver.BaseServer) -> None:
        if not Server.customer_set:
            Server.other_ports = get_other_ports(Customer)
            Server.balance = get_balance(Customer)
            Server.customer_set = True

        if not Server.genesis_block_created:
            Server.create_genesis_block()
            Server.genesis_block_created = True

        try:
            p_handle = open(self.PRIVATE_KEY_FILE)
        except IOError:
            print("private key does not exists")
            self.create_own_keys()
        finally:
            p_handle.close()
        
        self.private_key = RSA.import_key(open(Server.PRIVATE_KEY_FILE).read())
        self.public_key = RSA.import_key(open(Server.PUBLIC_KEY_FILE).read())
        self.pkcs1_15_object = pkcs1_15.new(self.private_key)
        super().__init__(request, client_address, server)
        
    def do_HEAD(self):
        return

    def do_POST(self):
        return

    def do_PUT(self):
        self.respond_PUT()
        return

    def do_GET(self):
        self.respond_GET()
        return

    def handle_GET(self):
        status = 200
        content_type = "text/plain"
        response_content = ""

        if self.path == "/createblockdata":
            try:
                response_content = self.create_and_send_block_data()
            except:
                response_content = "Cannot create block"
        elif self.path == "/getunverifiedtransactions":
            try:
                response_content = self.get_unverified_transactions()
            except:
                response_content = "Cannot get unverified transactions"
        elif self.path == "/getverifiedtransactions":
            try:
                response_content = self.get_verified_transactions()
            except:
                response_content = "Cannot get verified transactions"
        elif self.path == "/displayblock":
            try:
                response_content = self.get_number_of_blocks()
            except:
                response_content = "Cannot get number of blocks"
        elif self.path == "/mine":
            try:
                nonce, hash = self.check_and_mine()
                if hash == "failed":
                    response_content = nonce
                else:
                    response_content = "Hash: " + hash + " Nonce: " + nonce
            except:
                response_content = "Cannot mine the block"
        elif self.path == "/updateblockinnetwork":
            try:
                response_content = self.update_block_in_network()
            except:
                response_content = "Cannot update block"
        elif self.path == "/balance":
            try:
                response_content = self.get_balance()
            except:
                response_content = "Cannot get balance"
        elif self.path == "/honeylist":
            try:
                response_content = self.get_honey_list()
            except:
                response_content = "Cannot get honey list"

        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.end_headers()
        return bytes(response_content, "UTF-8")

    def handle_PUT(self):
        status = 200
        content_type = "text/plain"
        response_content = ""

        if self.path == "/verify":
            try:
                data_str = json.dumps(self.rfile.read(int(self.headers.get('Content-Length'))).decode())
                data_json = json.loads(json.loads(data_str))
                transaction = data_json["transaction"]
                signature = binascii.unhexlify(str(data_json["signature"]).encode())
                raw_key = binascii.unhexlify(str(data_json["public_key"]).encode())
                public_key = RSA.import_key(raw_key)
                result = self.verify_signature(transaction, signature, public_key)
                response_content = result
            except:
                response_content = "verification failed"
        elif self.path == "/verifytransaction":
            try:
                data_str = json.dumps(self.rfile.read(int(self.headers.get('Content-Length'))).decode())
                transaction = json.loads(json.loads(data_str))
                result = self.validate_transaction(transaction)
                response_content = result
            except:
                response_content = "Error in verification"
        elif self.path == "/unverifiedtransactions":
            try:
                data_str = json.dumps(self.rfile.read(int(self.headers.get('Content-Length'))).decode())
                data_json = json.loads(data_str)
                Server.unverified_transactions_string.append(data_json)
                response_content = "transaction saved"
            except:
                response_content = "transaction not saved"
        elif self.path == "/blockdata":
            try:
                data_str = json.dumps(self.rfile.read(int(self.headers.get('Content-Length'))).decode())
                Server.new_block_data = json.loads(json.loads(data_str))
                response_content = "Block data received"
            except:
                response_content = "Block data received"
        elif self.path == "/block":
            try:
                data_str = json.dumps(self.rfile.read(int(self.headers.get('Content-Length'))).decode())
                block = json.loads(json.loads(data_str))
                response_content = self.add_block_to_chain(block)
            except:
                response_content = "Block not added to chain"
        elif self.path =="/createtransaction":
            try:
                data_str = json.dumps(self.rfile.read(int(self.headers.get('Content-Length'))).decode())
                data_json = json.loads(json.loads(data_str))
                honey_name = data_json['honey_name']
                honey_quantity = data_json['honey_quantity']
                sender = data_json["sender"]
                recipient = data_json["recipient"]
                amount = data_json["amount"]
                self.create_and_send_transaction_data(honey_name, honey_quantity, sender, recipient, amount)
                response_content = "Transaction requested"
            except:
                response_content = "Transaction request failed"
        elif self.path =="/getblock":
            try:
                data_str = json.dumps(self.rfile.read(int(self.headers.get('Content-Length'))).decode())
                data_json = json.loads(json.loads(data_str))
                block_num = data_json["block_num"]
                block = self.get_block(block_num)
                response_content = block
            except:
                response_content = "Getting block failed"
        elif self.path =="/honey":
            try:
                data_str = json.dumps(self.rfile.read(int(self.headers.get('Content-Length'))).decode())
                data_json = json.loads(json.loads(data_str))
                response_content = self.add_honey(data_json)
            except:
                response_content = "Honey keeping failed"
        elif self.path =="/addhoney":
            try:
                data_str = json.dumps(self.rfile.read(int(self.headers.get('Content-Length'))).decode())
                data_json = json.loads(json.loads(data_str))
                Server.honey_list.append(data_json)
                response_content = "Honey keeping successful"
            except:
                response_content = "Honey keeping failed"
        elif self.path =="/isverified":
            try:
                data_str = json.dumps(self.rfile.read(int(self.headers.get('Content-Length'))).decode())
                transaction = json.loads(json.loads(data_str))
                response_content = self.is_verified(transaction)
            except:
                response_content = "error checking"
        elif self.path =="/removefromverified":
            try:
                data_str = json.dumps(self.rfile.read(int(self.headers.get('Content-Length'))).decode())
                transaction = json.loads(json.loads(data_str))
                self.remove_from_verified_transactions(transaction)
                response_content = "transaction removed"
            except:
                response_content = "error checking"
        elif self.path =="/cleanaftercreateblock":
            try:
                data_str = json.dumps(self.rfile.read(int(self.headers.get('Content-Length'))).decode())
                transaction = json.loads(json.loads(data_str))
                print(transaction)
                self.clean_after_create_block(transaction)
                response_content = "cleaning done"
            except:
                response_content = "error cleaning"

        self.send_response(status)
        self.send_header('Content-type', content_type)
        self.end_headers()
        return bytes(response_content, "UTF-8")

    def create_own_keys(self):
        self.private_key = RSA.generate(2048)

        private_hadle = open(self.PRIVATE_KEY_FILE, 'wb')
        private_hadle.write(self.private_key.export_key())
        private_hadle.close()

        self.public_key = self.private_key.public_key()
        public_hadle = open(self.PUBLIC_KEY_FILE, 'wb')
        public_hadle.write(self.public_key.export_key())
        public_hadle.close()

    def convert_transaction_to_bytes(self, transaction):
        new_transaction = transaction.copy()
        new_transaction["honey_name"] = str(transaction["honey_name"])
        new_transaction["honey_quantity"] = str(transaction["honey_quantity"])
        new_transaction["sender"] = str(transaction["sender"])
        new_transaction["recipient"] = str(transaction["recipient"])
        new_transaction["amount"] = str(transaction["amount"])
        return json.dumps(new_transaction, indent=2).encode('utf-8')

    def sign_transaction(self, transaction):
        transaction_dump = self.convert_transaction_to_bytes(transaction)
        hash = SHA256.new(transaction_dump)
        signature = self.pkcs1_15_object.sign(hash)
        return binascii.hexlify(signature).decode("UTF-8")

    def verify_signature(self, transaction, signature, public_key):
        transaction_dump = self.convert_transaction_to_bytes(transaction)
        hash = SHA256.new(transaction_dump)
        try:
            pb_object = pkcs1_15.new(public_key)
            pb_object.verify(hash, signature)
            print("The signature is valid.")
            return True
        except (ValueError, TypeError):
            print("The signature is not valid.")
            return False

    def get_unverified_transactions(self):
        transactions = []
        for transaction_str in Server.unverified_transactions_string:
            data = json.loads(transaction_str)
            transaction = data["transaction"]
            transactions.append(transaction)

        return json.dumps(transactions)

    def get_verified_transactions(self):
        return json.dumps(Server.verified_transactions)

    def get_honey_list(self):
        return json.dumps(Server.honey_list)

    def is_verified(self, transaction):
        for vtransaction in Server.verified_transactions:
            if (transaction["honey_name"] == vtransaction["honey_name"] and
                transaction["honey_quantity"] == vtransaction["honey_quantity"] and
                transaction["sender"] == vtransaction["sender"] and
                transaction["recipient"] == vtransaction["recipient"] and
                transaction["amount"] == vtransaction["amount"]):
                return "yes"

        return "no"

    def validate_transaction(self, transaction):
        for transaction_str in Server.unverified_transactions_string:
            data = json.loads(transaction_str)
            unverified_transaction = data["transaction"]
            if (transaction["honey_name"] == unverified_transaction["honey_name"] and
                transaction["honey_quantity"] == unverified_transaction["honey_quantity"] and
                transaction["sender"] == unverified_transaction["sender"] and
                transaction["recipient"] == unverified_transaction["recipient"] and
                transaction["amount"] == unverified_transaction["amount"]):
                signature = binascii.unhexlify(str(data["signature"]).encode())
                raw_key = binascii.unhexlify(str(data["public_key"]).encode())
                public_key = RSA.import_key(raw_key)
                if self.verify_signature(unverified_transaction, signature, public_key):
                    self.add_to_verified_transactions(unverified_transaction)
                    self.remove_from_unverified_transactions(transaction)
                    return "found_and_valid_signature"
                else:
                    self.remove_from_unverified_transactions(unverified_transaction)
                    return "found_but_invalid_signature"

        return "not_found"

    def add_to_verified_transactions(self, transaction):
        Server.verified_transactions.append(transaction)

    def remove_from_unverified_transactions(self, transaction):
        tmp_transactions = []
        for transaction_str in Server.unverified_transactions_string:
            data = json.loads(transaction_str)
            unverified_transaction = data["transaction"]
            if (transaction["honey_name"] == unverified_transaction["honey_name"] and
                transaction["honey_quantity"] == unverified_transaction["honey_quantity"] and
                transaction["sender"] == unverified_transaction["sender"] and
                transaction["recipient"] == unverified_transaction["recipient"] and
                transaction["amount"] == unverified_transaction["amount"]):
                continue

            tmp_transactions.append(transaction_str)

        Server.unverified_transactions_string = tmp_transactions

    def remove_from_verified_transactions(self, transaction):
        tmp_transactions = []
        for vtransaction in Server.verified_transactions:
            if (transaction["honey_name"] == vtransaction["honey_name"] and
                transaction["honey_quantity"] == vtransaction["honey_quantity"] and
                transaction["sender"] == vtransaction["sender"] and
                transaction["recipient"] == vtransaction["recipient"] and
                transaction["amount"] == vtransaction["amount"]):
                continue

            tmp_transactions.append(vtransaction)

        Server.verified_transactions = tmp_transactions

    def remove_from_honey_list(self, transaction):
        tmp_honey = []
        for honey in Server.honey_list:
            if (transaction["honey_name"] == honey["name"] and
                transaction["honey_quantity"] == honey["quantity"] and
                transaction["recipient"] == honey["owner"] and
                transaction["amount"] == honey["price"]):
                continue

            tmp_honey.append(honey)

        Server.honey_list = tmp_honey

    def create_transaction(self, honey_name, honey_quantity, sender, recipient, amount):
        transaction = Transaction()
        t = transaction.new_transaction(honey_name, honey_quantity, sender, recipient, amount)
        return t

    def create_genesis_block():
        block = Block()
        b = block.new_block()
        new_hash='0'*64
        b["hash"] = new_hash
        Server.chain.append(b)

    def get_decoded_publickey(self):
        public_key =  binascii.hexlify(self.public_key.export_key()).decode("UTF-8")   
        return public_key

    def create_and_send_transaction_data(self, honey_name, honey_quantity, sender, recipient, amount):
        transaction = self.create_transaction(honey_name, honey_quantity, sender, recipient, amount)
        signature = self.sign_transaction(transaction)
        #signature = str("kjghwefkwfhdwdfhlvwdgbh")
        public_key = self.get_decoded_publickey()
        transaction_data = {
            "transaction": transaction,
            "signature": signature,
            "public_key": public_key
        }

        for port in Server.other_ports:
            url = "http://localhost:" + str(port) + "/unverifiedtransactions"
            print("sending to", url)
            response = requests.put(url, json=transaction_data, verify=False)

        Server.verified_transactions.append(transaction)
        return str(response.content)

    def create_and_send_block_data(self):
        if len(Server.verified_transactions) == 0:
            return "empty_verified_transaction_list, no_block_created"

        index = len(Server.chain) + 1
        previous_hash = Server.chain[len(Server.chain)-1]["hash"]
        all_verified_transactions = []

        for t in Server.verified_transactions:
            count = 0
            for port in Server.other_ports:
                url = "http://localhost:" + str(port) + "/isverified"
                print("sending to", url)
                response = requests.put(url, json=t, verify=False)
                if "yes" in str(response.content):
                    count=count+1

            if count == len(Server.other_ports):
                all_verified_transactions.append(t)

        if len(all_verified_transactions) == 0:
            return "not everyone verified transactions"

        block_data = {
            "index" : index,
            "previous_hash" : previous_hash,
            "transactions" : all_verified_transactions,
            "timestamp" : time(),
        }

        for port in Server.other_ports:
            url = "http://localhost:" + str(port) + "/blockdata"
            print("sending to", url)
            response = requests.put(url, json=block_data, verify=False)

        Server.new_block_data = block_data

        for t in all_verified_transactions:
            for port in Server.other_ports:
                url = "http://localhost:" + str(port) + "/removefromverified"
                print("sending to", url)
                response = requests.put(url, json=t, verify=False)

            self.remove_from_verified_transactions(t)

        return "block_creation_requested"

    def create_block(self, index, transactions, previous_hash, timestamp, hash, nonce):
        block = Block()
        b = block.new_block() 
        b["Nonce"] = nonce
        b["previous_hash"] = previous_hash
        b["index"] = index
        b["transactions"] = transactions
        b["hash"] = hash
        b["timestamp"] = timestamp
        Server.new_block = b

    def get_number_of_blocks(self):
        return json.dumps(len(Server.chain))

    def get_balance(self):
        return json.dumps(Server.balance)  

    def get_block(self, block_num):
        block = dict(Server.chain[block_num-1])
        return json.dumps(block)

    def SHA256_func(self, text):
        results = sha256(text.encode("UTF-8")).hexdigest() 
        return results

    def add_block_to_chain(self, block):
        index_block = block["index"]
        index_block_inchain = len(Server.chain)
        if index_block <= index_block_inchain:
            return "block already exists"

        Server.chain.append(block)
        return "block added successfully"

    def update_block_in_network(self):
        index_block = Server.new_block["index"]
        index_block_inchain = len(Server.chain)
        if index_block <= index_block_inchain:
            return "block already exists"

        for port in Server.other_ports:
            url = "http://localhost:" + str(port) + "/block"
            print("sending to", url)
            response1 = requests.put(url, json=Server.new_block, verify=False)

        Server.chain.append(Server.new_block)

        for transaction in Server.new_block["transactions"]:
            for port in Server.other_ports:
                url = "http://localhost:" + str(port) + "/cleanaftercreateblock"
                print("sending to", url)
                requests.put(url, json=transaction, verify=False)

            self.clean_after_create_block(transaction)

        return str(response1.content)

    def add_honey(self, honey):
        for port in Server.other_ports:
            url = "http://localhost:" + str(port) + "/addhoney"
            print("sending to", url)
            response = requests.put(url, json=honey, verify=False)

        Server.honey_list.append(honey)
        return str(response.content)

    def check_and_mine(self):
        if not any(Server.new_block_data.values()):
            return "no_block_data_found", "failed"

        index_block_data = Server.new_block_data["index"]
        index_block_inchain = len(Server.chain)
        if index_block_data <= index_block_inchain:
             return "no_new_block_data_found", "failed"

        index = Server.new_block_data["index"]
        transactions = Server.new_block_data["transactions"]
        previous_hash = Server.new_block_data["previous_hash"]
        timestamp = Server.new_block_data["timestamp"]
        nonce, hash = self.mine(index, transactions, previous_hash, timestamp, self.DIFFICULTY)
        if hash == "failed":
            return nonce, hash

        self.create_block(index, transactions, previous_hash, timestamp, hash, nonce)

        return nonce, hash

    def mine(self, index, transactions, previous_hash, timestamp, zeros_to_prefix):   
        MAX_NONCE_LIMIT=10000000 
        prefix='0'*zeros_to_prefix
        for nonce in range(MAX_NONCE_LIMIT):
            text = str(index) + str(transactions) + str(previous_hash) + str(timestamp) + str(nonce)
            hash = self.SHA256_func(text)
            if hash.startswith(prefix):
                print("Block mined, nonce value :",nonce)
                return str(nonce), hash

        print("Could not calculate hash with Nonce limit: ", MAX_NONCE_LIMIT)
        return "could_not_calculate_hash", "failed"

    def clean_after_create_block(self, transaction):
        print(transaction["sender"])
        print(Customer)
        if transaction["sender"] == Customer:
            Server.balance = Server.balance - int(transaction["amount"])

        if transaction["recipient"] == Customer:
            Server.balance = Server.balance + int(transaction["amount"])

        self.remove_from_honey_list(transaction)

    def respond_GET(self):
        content = self.handle_GET()
        self.wfile.write(content)

    def respond_PUT(self):
        content = self.handle_PUT()
        self.wfile.write(content)
