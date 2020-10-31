import socket
import time
import random

import Crypto
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

data_for_server = {'TCP_IP': '127.0.0.1', 'TCP_PORT': 3000, "BUFFER_SIZE": 1024}
AES_data = {'K3': b'1234567891234568', 'iv': b'\xad\xbe\xf6\xc2\xb3p\x10I\xc6\x96 M\xb9\xa1\x96b'}
mode = None
KM = dict()
KM["CBC_key"] = b'abcdabcdabcdabcd'
KM["OFB_key"] = b'abcdabcdabcdabcd'
KM["KEY_3"] = AES_data["K3"]
print("Km server started")


def get_encryption_type():
    data = ["CBC", "OFB"]
    return random.choice(data)


while 1:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((data_for_server["TCP_IP"], data_for_server['TCP_PORT']))
    s.listen(1)
    conn, addr = s.accept()
    data = conn.recv(data_for_server["BUFFER_SIZE"])
    data = data.decode()
    if not data: break
    print("Node KM received data: ", data)
    if data == "CBC":
        mode = "CBC"
        aes = AES.new(AES_data["K3"], AES.MODE_ECB)
        aes_key = aes.encrypt(pad(KM["CBC_key"], AES.block_size))
        conn.send(aes_key)
        time.sleep(1)
        aes = AES.new(AES_data["K3"], AES.MODE_ECB)
        aes_iv = aes.encrypt(AES_data['iv'])
        conn.send(aes_iv)
        time.sleep(1)
    elif data == "OFB":
        mode = "OFB"
        aes = AES.new(AES_data["K3"], AES.MODE_ECB)
        aes_key = aes.encrypt(pad(KM["OFB_key"], AES.block_size))
        conn.send(aes_key)
        time.sleep(1)
        print(AES_data['iv'])
        aes = AES.new(AES_data["K3"], AES.MODE_ECB)
        aes_iv = aes.encrypt(AES_data['iv'])
        conn.send(aes_iv)
        print(aes_iv)
        time.sleep(1)
    elif data == 'key_refresh':
        aes = AES.new(AES_data["K3"], AES.MODE_ECB)
        AES_data['iv'] = Crypto.Random.get_random_bytes(AES.block_size)
        aes_key = None
        if mode == "CBC":
            KM["CBC_key"] = Crypto.Random.get_random_bytes(AES.block_size)
            aes_key = aes.encrypt(pad(KM["CBC_key"], 16))
        elif mode == "OFB":
            KM["OFB_key"] = Crypto.Random.get_random_bytes(AES.block_size)
            aes_key = aes.encrypt(pad(KM["OFB_key"], 16))
        conn.send(aes_key)
        aes = AES.new(AES_data["K3"], AES.MODE_ECB)
        aes_iv = aes.encrypt(AES_data['iv'])
        conn.send(aes_iv)
        time.sleep(1)
        conn.send(get_encryption_type().encode())
    else:
        conn.send("does not exist".encode())
conn.close()
