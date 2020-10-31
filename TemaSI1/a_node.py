import socket
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import mmap
import time
import CBC
import OFB
import random

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
done = False
q = 3
key_refresh = 0


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
    CBC_encrypt_text = CBC.key_encrypt_CBC(xored_text, AES_data['key'])
    return CBC_encrypt_text


def encode_CBC(text, last_element):
    xored_text = CBC.xor(text, last_element)
    CBC_encrypt_text = CBC.key_encrypt_CBC(xored_text, AES_data['key'])
    return CBC_encrypt_text


def send_data_CBC(conn, map, start, end):
    global q
    global key_refresh
    last_encoded_element = None
    is_first_iteration = True
    if end < 16:
        text = map[0:len(map)]
        encoded_text = first_iteration_CBC(text)
        conn.send(encoded_text)
        time.sleep(1)
    else:
        while start < end:
            key_refresh += 1
            print("Key refresh:", key_refresh)
            if key_refresh == q:
                time.sleep(1)
                print("Key refrshing")
                conn.send("key_refresh".encode())
                km_client = get_km_client_conn()
                km_client.send('key_refresh'.encode())
                received = km_client.recv(1024)
                mode = km_client.recv(1024)
                km_client.close()
                AES_data['key'] = aes_ecb_decrypt(received)
                conn.send(received)
                time.sleep(1)
                conn.send(mode)
                key_refresh = 0
                start_transfer(mode, conn, map, start, end)
            text = map[start:(start + 16)]
            if is_first_iteration:
                encoded_text = first_iteration_CBC(text)
                last_encoded_element = encoded_text
                is_first_iteration = False
                conn.send(encoded_text)
            else:
                CBC_encrypt = encode_CBC(text, last_encoded_element)
                time.sleep(1)
                conn.send(CBC_encrypt)
                time.sleep(1)
                conn.send(last_encoded_element)
                last_encoded_element = CBC_encrypt
            start += 16
    time.sleep(1)
    conn.send("Done".encode())
    conn.close()
    global done
    done = True
    print("Whole data sent")


def first_iteration_OFB(text):
    ofb_enc = OFB.key_encrypt_OFB(AES_data["iv"], AES_data["key"])
    OFB_encrypt_text = OFB.xor(ofb_enc, text)
    return OFB_encrypt_text, ofb_enc


def get_next_iteration(text, last_element):
    xored_text = OFB.key_encrypt_OFB(last_element, AES_data["key"])
    OFB_encrypt_text = OFB.xor(xored_text, text)
    return OFB_encrypt_text, xored_text


def send_data_OFB(conn, map, start, end):
    global q
    global key_refresh
    global done
    done = True
    last_encoded_element = None
    is_first_iteration = True
    if end < 16:
        text = map[0:len(map)]
        encoded_text, last_encoded_element = first_iteration_OFB(text)
        conn.send(encoded_text)
        done = True
        time.sleep(1)
    else:
        while start < end:
            key_refresh += 1
            text = map[start:(start + 16)]
            if key_refresh == q:
                time.sleep(1)
                print("Key refrshing")
                conn.send("key_refresh".encode())
                km_client = get_km_client_conn()
                km_client.send('key_refresh'.encode())
                received = km_client.recv(1024)
                mode = km_client.recv(1024)
                print("New mode:", mode)
                km_client.close()
                AES_data['key'] = aes_ecb_decrypt(received)
                conn.send(received)
                time.sleep(1)
                conn.send(mode)
                key_refresh = 0
                start_transfer(mode.decode(), conn, map, start, end)
            if is_first_iteration:
                encoded_text, last_encoded_element = first_iteration_OFB(text)
                is_first_iteration = False
                conn.send(encoded_text)
            else:
                encoded_text, last_encoded_element = get_next_iteration(text, last_encoded_element)
                conn.send(encoded_text)
            start += 16
    time.sleep(1)
    conn.send("Done".encode())
    done = True
    print("Whole data sent")


def get_encryption_type():
    data = ["CBC", "OFB"]
    return random.choice(data)


def start_transfer(data, conn, map, start, end):
    if data == 'CBC':
        send_data_CBC(conn, map, start, end)
    else:
        send_data_OFB(conn, map, start, end)


def start_server():
    global can_do_transfer
    with open("text_to_send", "r+") as f:
        map = mmap.mmap(f.fileno(), 0)
        map.readline()
    while 1:
        if done:
            conn.close()
            return
        # sender = get_encryption_type()
        sender = "CBC"
        print("Selected mode:", sender)
        conn.send(sender.encode())
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
            start_transfer(data, conn, map=map, start=0, end=len(map))


if __name__ == "__main__":
    start_server()
