import socket
import random
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad

host_ip, server_port = "127.0.0.1", 5005
tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_client.connect((host_ip, server_port))
K3 = ''.join(chr(random.randint(0, 0xFF)) for i in range(16))
input_available = True
AES_data = {'K3': '1234567891234568', 'iv': b'\xad\xbe\xf6\xc2\xb3p\x10I\xc6\x96 M\xb9\xa1\x96b'}
encryption_type_dict = {"CBC": AES.MODE_CBC, "OFB": AES.MODE_OFB}
encryption_type = None
key_to_use = None
recieving_new_key = False
print("Client started")


def get_encryption_type():
    encryption_type = input("Node A Choose: CBC or OFB: ")
    return encryption_type


try:
    while True:
        data = get_encryption_type()
        print(data)
        input_available = False
        tcp_client.sendall(data.encode())
        received = tcp_client.recv(1024)
        print("Am primit", received)
        aes = AES.new(AES_data["K3"].encode("utf8"), AES.MODE_ECB)
        aes_key = aes.decrypt(received)
        key_to_use = unpad(aes_key, 16)
        print(key_to_use)
        received = tcp_client.recv(1024)
        while received != b"Done":
            if recieving_new_key:
                print(received)
                recieving_new_key = False
            elif received == b'key_refresh' and not recieving_new_key:
                print("Urmeaza sa primim cheia de refresh")
                recieving_new_key = True
            else:
                print(received)
            received = tcp_client.recv(1024)
except Exception as ex:
    print(ex)
    tcp_client.close()
