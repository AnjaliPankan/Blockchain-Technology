from time import time

class Block():
    def new_block(self):
        block = {
            'index': 1,
            'Nonce': 0,
            'hash': '',
            'previous_hash': '',
            'timestamp': time(),
            'transactions': []
        }
        return block