import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import mmap
import time
import CBC
import OFB

AES_data = {'K3': b'1234567891234568', 'iv': b'\xad\xbe\xf6\xc2\xb3p\x10I\xc6\x96 M\xb9\xa1\x96b', 'key': None}
print("Server started")
TCP_IP = '127.0.0.1'
TCP_PORT = 5005
BUFFER_SIZE = 1024
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind((TCP_IP, TCP_PORT))
s.listen(1)
conn, addr = s.accept()
can_do_transfer = False
mode = None


def get_km_client_conn():
    host_ip_km, server_port_km = "127.0.0.1", 3000
    km_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    km_client.connect((host_ip_km, server_port_km))
    return km_client


def aes_ecb_decrypt(cypher):
    aes = AES.new(AES_data["K3"], AES.MODE_ECB)
    aes_key = aes.decrypt(cypher)
    return unpad(aes_key, 16)


def first_iteration_CBC(text):
    xored_text = CBC.xor(text, AES_data['iv'])
    xored_text = "~".join(letter for letter in xored_text)
    CBC_encrypt_text = CBC.key_encrypt_CBC(xored_text, AES_data['key'])
    return CBC_encrypt_text


def encode_CBC(text, last_element):
    xored_text = CBC.xor(text, last_element.encode())
    xored_text = "~".join(letter for letter in xored_text)
    CBC_encrypt_text = CBC.key_encrypt_CBC(xored_text, AES_data['key'])
    return CBC_encrypt_text


def send_data_CBC(conn):
    q = 0
    last_encoded_element = None
    is_first_iteration = True
    with open("text_to_send", "r+") as f:
        map = mmap.mmap(f.fileno(), 0)
        map.readline()
    start = 0
    end = len(map)
    if end < 16:
        text = map[0:len(map)]
        encoded_text = first_iteration_CBC(text)
        conn.send(encoded_text.encode())
        time.sleep(1)
    else:
        while start < end:
            q += 1
            text = map[start:(start + 16)]
            if is_first_iteration:
                encoded_text = first_iteration_CBC(text)
                last_encoded_element = encoded_text
                is_first_iteration = False
                conn.send(encoded_text.encode())
            else:
                print(last_encoded_element)
                CBC_encrypt = encode_CBC(text, last_encoded_element)
                conn.send((CBC_encrypt + "LAST_ELEM" + last_encoded_element).encode())
                last_encoded_element = CBC_encrypt
            if q == 2:
                time.sleep(1)
                print("Key refrshing")
                conn.send("key_refresh".encode())
                km_client = get_km_client_conn()
                km_client.send('key_refresh'.encode())
                received = km_client.recv(1024)
                km_client.close()
                AES_data['key'] = aes_ecb_decrypt(received)
                conn.send(received)
                q = 0
            start += 16
    time.sleep(1)
    conn.send("Done".encode())
    print("Whole data sent")


def first_iteration_OFB(text):
    xored_text = OFB.key_encrypt_OFB(AES_data["iv"], AES_data["key"])
    OFB_encrypt_text = OFB.xor(xored_text.encode(), text)
    OFB_text = "~".join(letter for letter in OFB_encrypt_text)
    return OFB_text


def send_data_OFB(conn):
    q = 0
    last_encoded_element = None
    is_first_iteration = True
    with open("text_to_send", "r+") as f:
        map = mmap.mmap(f.fileno(), 0)
        map.readline()
    start = 0
    end = len(map)
    if end < 16:
        text = map[0:len(map)]
        encoded_text = first_iteration_OFB(text)
        conn.send(encoded_text.encode())
        time.sleep(1)
    else:
        while start < end:
            q += 1
            text = map[start:(start + 16)]
            if is_first_iteration:
                encoded_text = first_iteration_OFB(text)
                last_encoded_element = encoded_text
                is_first_iteration = False
                conn.send(encoded_text.encode())
            else:
                print(last_encoded_element)
                CBC_encrypt = encode_CBC(text, last_encoded_element)
                conn.send((CBC_encrypt + "LAST_ELEM" + last_encoded_element).encode())
                last_encoded_element = CBC_encrypt
            if q == 2:
                time.sleep(1)
                print("Key refrshing")
                conn.send("key_refresh".encode())
                km_client = get_km_client_conn()
                km_client.send('key_refresh'.encode())
                received = km_client.recv(1024)
                km_client.close()
                AES_data['key'] = aes_ecb_decrypt(received)
                conn.send(received)
                q = 0
            start += 16
    time.sleep(1)
    conn.send("Done".encode())
    print("Whole data sent")


while 1:
    data = conn.recv(BUFFER_SIZE)
    data = data.decode()
    if not data: break
    km_client = get_km_client_conn()
    km_client.send(data.encode())
    received = km_client.recv(1024)
    km_client.close()
    if data == 'CBC':
        mode = "CBC"
        can_do_transfer = True
        AES_data['key'] = aes_ecb_decrypt(received)
        conn.send(received)
    elif data == "OFB":
        mode = "OFB"
        can_do_transfer = True
        AES_data['key'] = aes_ecb_decrypt(received)
        conn.send(received)
    else:
        conn.send("No such mode".encode())
    if can_do_transfer:
        print("AES data: ", AES_data['key'])
        if data == 'CBC':
            send_data_CBC(conn)
        else:
            send_data_OFB(conn)
conn.close()
