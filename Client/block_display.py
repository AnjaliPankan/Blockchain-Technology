from lib2to3.pgen2.token import NUMBER
from operator import index
import pywebio
from pywebio.input import input, NUMBER
from pywebio.output import put_text, put_table, put_buttons, put_code, put_row
import requests
import json
import sys

from functools import partial

NETWORK_FILE = "../network.json"
total_block = 0
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

    own_port = data["block_display_port"]
    server_port = data["server_port"]

    if data["minor"] == "yes":
        minor = True

def edit_index(choice, row):
    put_text("You click %s button ar row %s" % (choice, row))

def edit_hash(choice, row):
    put_text("You click %s button ar row %s" % (choice, row))

def edit_Previous_hash(choice, row):
    put_text("You click %s button ar row %s" % (choice, row))

def edit_timestamp(choice, row):
    put_text("You click %s button ar row %s" % (choice, row))

def edit_transactions(choice, row):
    put_text("You click %s button ar row %s" % (choice, row))

def edit_nonce(choice, row):
    put_text("You click %s button ar row %s" % (choice, row))

def validate_blocknum(block_num):
    if block_num <= 0 or block_num > total_block:
        return "Please provide a valid block numer"

def block_display():
    global total_block
    url1 = "http://localhost:" + str(server_port) + "/displayblock"
    response = requests.get(url1, verify=False)
    total_block = int(response.content.decode("UTF-8"))
    put_text("Total number of Blocks: %d" % total_block)

    block_num = input("Get Block number:", type=NUMBER, validate=validate_blocknum)

    block_num_data = {
        "block_num": block_num, 
    }
    url2 = "http://localhost:" + str(server_port) + "/getblock"
    response = requests.put(url2, json=block_num_data, verify=False)
    data_str = json.dumps(response.content.decode())
    data_json = json.loads(json.loads(data_str))
    #put_table([["Details","Values"],
     #           ["Block", data_json["index"], put_buttons(['edit'], onclick=partial(edit_index, row=1))],
      #          ["Timestamp", data_json["timestamp"], put_buttons(['edit'], onclick=partial(edit_timestamp, row=4))],
       #         ["Nonce", data_json["Nonce"], put_buttons(['edit'], onclick=partial(edit_nonce, row=6))],
        #        ["Transactions", data_json["transactions"], put_buttons(['edit'], onclick=partial(edit_transactions, row=5))],
         #       ["Previous hash", data_json["previous_hash"], put_buttons(['edit'], onclick=partial(edit_Previous_hash, row=3))],
          #      ["Hash", data_json["hash"], put_buttons(['edit'], onclick=partial(edit_hash, row=2))],  
           #     ]).style('font-size: 20px')

    put_table([
        [put_row([put_code('Block'), None, put_code(data_json["index"]), put_buttons(['edit'], onclick=partial(edit_index,row =1))], size='20% 10px 80%')],
        [put_row([put_code('Timestamp'), None, put_code(data_json["timestamp"]), put_buttons(['edit'], onclick=partial(edit_timestamp,row =2))], size='20% 10px 80%')],
        [put_row([put_code('Nonce'), None, put_code(data_json["Nonce"]), put_buttons(['edit'], onclick=partial(edit_nonce,row =3))], size='20% 10px 80%')],
        [put_row([put_code('Transactions'), None, put_code(data_json["transactions"]), put_buttons(['edit'], onclick=partial(edit_transactions,row =4))], size='20% 10px 80%')],
        [put_row([put_code('Previous hash'), None, put_code(data_json["previous_hash"]), put_buttons(['edit'], onclick=partial(edit_Previous_hash,row =5))], size='19% 10px 81%')],
        [put_row([put_code('Hash'), None, put_code(data_json["hash"]), put_buttons(['edit'], onclick=partial(edit_hash,row =6))], size='20% 10px 80%')]
    ]).style('font-size: 15px')

if __name__ == '__main__':
    if len(sys.argv) > 2:
        print("more than one argument passed")
        sys.exit()

    for i, arg in enumerate(sys.argv):
        if i == 1:
            Customer_name = arg

    get_port()
    pywebio.start_server(block_display, port=own_port)
