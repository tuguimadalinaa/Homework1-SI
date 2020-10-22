import socket
from Crypto.Cipher import AES

AES_data = {'K3': '1234567891234568', 'iv': b'\xad\xbe\xf6\xc2\xb3p\x10I\xc6\x96 M\xb9\xa1\x96b'}

TCP_IP = '127.0.0.1'
TCP_PORT = 5005
BUFFER_SIZE = 1024
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)
conn, addr = s.accept()
print('Connection address: ', addr)
q = 0
while 1:
    data = conn.recv(BUFFER_SIZE)
    data = data.decode()
    if not data: break
    host_ip_km, server_port_km = "127.0.0.1", 3000
    km_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    km_client.connect((host_ip_km, server_port_km))
    km_client.sendall(data.encode())
    received = km_client.recv(1024)
    km_client.close()
    if data == 'CBC':
        aes = AES.new(AES_data["K3"].encode("utf8"), AES.MODE_CBC, AES_data["iv"])
        aes_key = aes.decrypt(received)
        print(aes_key)
        conn.send(received)
    elif data == "OFB":
        aes = AES.new(AES_data["K3"].encode("utf8"), AES.MODE_OFB, AES_data["iv"])
        aes_key = aes.decrypt(received)
        print(aes_key)
        conn.send(aes_key)
    else:
        conn.send(data.encode())
conn.close()
