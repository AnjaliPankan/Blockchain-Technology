import pywebio
from pywebio.input import input, input_group, TEXT, NUMBER
from pywebio.output import put_text, put_buttons
import requests
import json
import sys

from functools import partial

NETWORK_FILE = "../network.json"
Customer_name = ""
own_port = 0
server_port = 0
minor = False

def get_port():
    global own_port
    global server_port
    global minor
    try:
        with open(NETWORK_FILE) as f:
            d = json.load(f)
    except IOError:
        print("network file does not exists")
        sys.exit()

    try:
        data = d[Customer_name]
    except:
        print("customer data not found")
        sys.exit()

    own_port = data["transaction_input_port"]
    server_port = data["server_port"]

    if data["minor"] == "yes":
        minor = True

def buy_honey(choice, row):
    data = json.loads(row)

    url1 = "http://localhost:" + str(server_port) + "/balance"
    response = requests.get(url1, verify=False)
    balance = int(response.content.decode("UTF-8"))
    if balance < data['price']:
        put_text("Your balance: ", balance, "is lower than price: ", data['price'])
    else:
        put_text("Buying honey: ", data['name'], " owner: ", data['owner'], " quantity: ", data['quantity'], " price: ", data['price'])

        transaction_input_data = {
            "honey_name": data['name'],
            "honey_quantity": data['quantity'],
            "sender": Customer_name,
            "recipient": data['owner'],
            "amount": data['price'],
        }
        url = "http://localhost:" + str(server_port) + "/createtransaction"
        response = requests.put(url, json=transaction_input_data, verify=False)
        put_text("Transaction created! response received: ", response.content.decode("UTF-8"))


def sell():
    data = input_group("Honey Details", [ 
    input("Honey Name", name = 'name', type=TEXT),
    input("Honey Quantity (mL)", name = 'quantity',type=NUMBER),
    input("Honey Price (crypto-currency X)", name = 'price',type=NUMBER)])

    honey = {
        "name": data["name"],
        "owner": Customer_name,
        "quantity": data["quantity"],
        "price": data["price"]
    }
    url3 = "http://localhost:" + str(server_port) + "/honey"
    response = requests.put(url3, json=honey, verify=False)
    put_text("Ready to sell request returned: ", response.content.decode("UTF-8"))

def buy():
    url2 = "http://localhost:" + str(server_port) + "/honeylist"
    response = requests.get(url2, verify=False)
    honeys = response.content.decode("UTF-8")
    data = json.loads(honeys)

    put_text("Available Honey: {")
    for honey in data:
        t = json.dumps(honey)
        put_text(t)
        put_buttons(['buy'], onclick=partial(buy_honey, row=t))
    put_text("}")

def sell_buy(choice):
    if choice == "Keep_honey":
        sell()
    else:
        buy()

def transaction_input():
    url1 = "http://localhost:" + str(server_port) + "/balance"
    response = requests.get(url1, verify=False)
    balance = int(response.content.decode("UTF-8"))

    put_text("Name: ", Customer_name, "\t\tBalance: ", balance, "\t\tMinor: ", str(minor))

    put_buttons(["Keep_honey", "Buy_honey"], onclick=partial(sell_buy))

if __name__ == '__main__':
    if len(sys.argv) > 2:
        print("more than one argument passed")
        sys.exit()

    for i, arg in enumerate(sys.argv):
        if i == 1:
            Customer_name = arg

    get_port()
    pywebio.start_server(transaction_input, port=own_port)
