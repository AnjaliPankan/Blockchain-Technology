class Transaction():
    def new_transaction(self, honey_name, honey_quantity, sender, recipient, amount):
        transaction = {
            'honey_name' : honey_name,
            'honey_quantity' : honey_quantity,
            'sender': sender,
            'recipient' : recipient,
            'amount' : amount
        }
        return transaction
        