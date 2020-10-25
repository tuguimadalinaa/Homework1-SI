import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import mmap
import time

AES_data = {'K3': b'1234567891234568', 'iv': b'\xad\xbe\xf6\xc2\xb3p\x10I\xc6\x96 M\xb9\xa1\x96b'}
print("Server started")
TCP_IP = '127.0.0.1'
TCP_PORT = 5005
BUFFER_SIZE = 1024
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)
conn, addr = s.accept()
q = 0

while 1:
    data = conn.recv(BUFFER_SIZE)
    data = data.decode()
    if not data: break
    host_ip_km, server_port_km = "127.0.0.1", 3000
    km_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    km_client.connect((host_ip_km, server_port_km))
    km_client.send(data.encode())
    received = km_client.recv(1024)
    km_client.close()
    if data == 'CBC':
        aes = AES.new(AES_data["K3"], AES.MODE_ECB)
        aes_key = aes.decrypt(received)
        print(unpad(aes_key, 16))
        conn.send(received)
        print("O sa mai trimit:")
        with open("text_to_send", "r+") as f:
            map = mmap.mmap(f.fileno(), 0)
            map.readline()
            print(len(map))
        start = 0
        end = len(map)
        while start < end:
            q += 1
            conn.send(map[start:(start + 16)])
            if q == 3:
                time.sleep(1)
                print("Key refrshing")
                conn.send("key_refresh".encode())
                km_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                km_client.connect((host_ip_km, server_port_km))
                km_client.send('key_refresh'.encode())
                received = km_client.recv(1024)
                km_client.close()
                conn.send(received)
                q = 0
            start += 16
        time.sleep(1)
        conn.send("Done".encode())
    elif data == "OFB":
        aes = AES.new(AES_data["K3"], AES.MODE_ECB)
        aes_key = aes.decrypt(received)
        print(unpad(aes_key, 16))
        conn.send(aes_key)
    else:
        conn.send(data.encode())
conn.close()
