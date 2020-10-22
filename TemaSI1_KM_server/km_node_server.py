import socket

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

data_for_server = {'TCP_IP': '127.0.0.1', 'TCP_PORT': 3000, "BUFFER_SIZE": 1024}
AES_data = {'K3': '1234567891234568', 'iv': b'\xad\xbe\xf6\xc2\xb3p\x10I\xc6\x96 M\xb9\xa1\x96b'}

KM = dict()
KM["CBC_key"] = 'cheia_unu'
KM["OFB_key"] = 'cheia_doi'
KM["KEY_3"] = AES_data["K3"]
while 1:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.bind((data_for_server["TCP_IP"], data_for_server['TCP_PORT']))
    s.listen(1)
    conn, addr = s.accept()
    data = conn.recv(data_for_server["BUFFER_SIZE"])
    data = data.decode()
    if not data:
        break
    print("Node KM received data: ", data)
    if data == "CBC":
        aes = AES.new(AES_data["K3"].encode("utf8"), AES.MODE_CBC, AES_data["iv"])
        aes_key = aes.encrypt(pad(KM["CBC_key"].encode("utf8"), AES.block_size))
        print(aes_key)
        conn.send(aes_key)
    elif data == "OFB":
        aes = AES.new(AES_data["K3"].encode("utf8"), AES.MODE_OFB, AES_data["iv"])
        aes_key = aes.encrypt(pad(KM["OFB_key"].encode("utf8"), AES.block_size))
        print(aes_key)
        conn.send(aes_key)
    else:
        conn.send("does not exist".encode())
