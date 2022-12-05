import time
import threading
import socket
from http.server import HTTPServer
import sys
import json

import blockchain
from blockchain import Server

HOST_NAME = "localhost"
NETWORK_FILE = "network.json"
Customer_name = ""

def get_port():
    global Customer_name
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

    return data["server_port"]

# https://stackoverflow.com/questions/46210672/python-2-7-streaming-http-server-supporting-multiple-connections-on-one-port
sock = socket.socket (socket.AF_INET, socket.SOCK_STREAM)
sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

class Thread(threading.Thread):
    def __init__(self, i):
        threading.Thread.__init__(self)
        self.i = i
        self.daemon = True
        self.start()
    def run(self):
        httpd = HTTPServer(addr, Server, False)
        httpd.socket = sock
        httpd.server_bind = self.server_close = lambda self: None
        httpd.serve_forever()

if __name__ == '__main__':
    if len(sys.argv) > 2:
        print("more than one argument passed")
        sys.exit()

    for i, arg in enumerate(sys.argv):
        if i == 1:
            Customer_name = arg

    blockchain.Customer = Customer_name

    port = get_port()
    addr = (HOST_NAME, port)
    sock.bind(addr)
    sock.listen(5)
    try:
        [Thread(i) for i in range(100)]
        print(time.asctime(), 'Server UP - %s:%s' % (HOST_NAME, port))
        value = True
        while(value):
            time.sleep(10)
    except KeyboardInterrupt:
        pass
    print(time.asctime(), 'Server DOWN - %s:%s' % (HOST_NAME, port))
