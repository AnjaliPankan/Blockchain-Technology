from unittest import result
import pywebio
from pywebio.input import input, input_group, TEXT, NUMBER
from pywebio.output import put_text, put_table, put_buttons
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

    own_port = data["pending_transaction_display_port"]
    server_port = data["server_port"]

    if data["minor"] == "yes":
        minor = True

def verify(choice, row):
    url = "http://localhost:" + str(server_port) + "/verifytransaction"
    transaction = json.loads(row)
    response = requests.put(url, json=transaction, verify=False)
    result = response.content.decode("UTF-8")
    put_text("verifying transaction %s returned: %s" % (row, result))

def create_block(chioce):
    url1 = "http://localhost:" + str(server_port) + "/createblockdata"
    response = requests.get(url1, verify=False)
    result = response.content.decode("UTF-8")
    put_text("creating block requested: ", (result))

    url2 = "http://localhost:" + str(server_port) + "/mine"
    response = requests.get(url2, verify=False)
    result = response.content.decode("UTF-8")
    put_text("minig requested: ", (result))

    url3 = "http://localhost:" + str(server_port) + "/updateblockinnetwork"
    response = requests.get(url3, verify=False)
    result = response.content.decode("UTF-8")
    put_text("update block in network requested: ", (result))

def pending_transaction_display():
    url0 = "http://localhost:" + str(server_port) + "/balance"
    response = requests.get(url0, verify=False)
    balance = int(response.content.decode("UTF-8"))

    put_text("Name: ", Customer_name, "\t\tBalance: ", balance, "\t\tMinor: ", str(minor))

    url1 = "http://localhost:" + str(server_port) + "/getunverifiedtransactions"
    response = requests.get(url1, verify=False)
    unverifiedtransactions = response.content.decode("UTF-8")
    data1 = json.loads(unverifiedtransactions)

    url2 = "http://localhost:" + str(server_port) + "/getverifiedtransactions"
    response = requests.get(url2, verify=False)
    verifiedtransactions = response.content.decode("UTF-8")
    data2 = json.loads(verifiedtransactions)

    put_text("Unverified Transactions: {")
    for trans in data1:
        t = json.dumps(trans)
        put_text(t)
        put_buttons(['verify'], onclick=partial(verify, row=t))
    put_text("}")

    put_text("Verified Transactions: {")
    exists = False 
    for trans in data2:
        exists = True
        t = json.dumps(trans)
        put_text(t)
    put_text("}")

    if minor and exists:
        put_buttons(['create block'], onclick=partial(create_block))

if __name__ == '__main__':
    if len(sys.argv) > 2:
        print("more than one argument passed")
        sys.exit()

    for i, arg in enumerate(sys.argv):
        if i == 1:
            Customer_name = arg

    get_port()
    pywebio.start_server(pending_transaction_display, port=own_port)
