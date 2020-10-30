import socket
from time import sleep

from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import CBC
import OFB

host_ip, server_port = "127.0.0.1", 5005
tcp_client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
tcp_client.connect((host_ip, server_port))
input_available = True
AES_data = {'K3': '1234567891234568', 'iv': b'\xad\xbe\xf6\xc2\xb3p\x10I\xc6\x96 M\xb9\xa1\x96b', 'key': None}
encryption_type_dict = {"CBC": AES.MODE_CBC, "OFB": AES.MODE_OFB}
encryption_type = None
key_to_use = None
recieving_new_key = False
print("Client started")
first_iteration = True


def aes_ecb_decrypt(cypher):
    aes = AES.new(AES_data["K3"].encode("utf8"), AES.MODE_ECB)
    aes_key = aes.decrypt(cypher)
    return unpad(aes_key, 16)


def get_first_iteration_CBC(text):
    CBC_text = CBC.key_decrypt_CBC(text, AES_data['key'])
    final_string = CBC.xor(CBC_text, AES_data['iv'])
    print("".join(letter for letter in [chr(int(x)) for x in final_string]))
    return "".join(letter for letter in [chr(int(x)) for x in final_string])


def get_decoded(text, last_element):
    CBC_decrypt = CBC.key_decrypt_CBC(text, AES_data['key'])
    result = CBC.xor(CBC_decrypt, last_element)
    return "".join(letter for letter in [chr(int(x)) for x in result])


def get_first_iteration_OFB(received):
    OFB_encrypt = OFB.key_encrypt_OFB(AES_data["iv"], AES_data["key"])
    result = OFB.xor(received, OFB_encrypt)
    return "".join(letter for letter in [chr(int(x)) for x in result]), OFB_encrypt


def get_decoded_OFB(text, last_element):
    OFB_encrypt = OFB.key_encrypt_OFB(last_element, AES_data['key'])
    result = OFB.xor(text, OFB_encrypt)
    return "".join(letter for letter in [chr(int(x)) for x in result]), OFB_encrypt


whole_text = ""
while True:
    data = tcp_client.recv(1024).decode()
    print("Node A has chosen: ", data)
    input_available = False
    tcp_client.sendall(data.encode())
    received = tcp_client.recv(1024)
    AES_data['key'] = aes_ecb_decrypt(received)
    received = tcp_client.recv(1024)
    last_element = None
    if data:
        while received != b"Done":
            if recieving_new_key:
                AES_data['key'] = aes_ecb_decrypt(received)
                recieving_new_key = False
            elif received == b'key_refresh' and not recieving_new_key:
                print("Urmeaza sa primim cheia de refresh")
                recieving_new_key = True
            else:
                if first_iteration:
                    first_iteration = False
                    if data == "CBC":
                        response = get_first_iteration_CBC(received)
                        whole_text += response
                    elif data == "OFB":
                        response, last_element = get_first_iteration_OFB(received)
                        whole_text += response
                else:
                    if data == "CBC":
                        response = received
                        last_element = tcp_client.recv(1024)
                        response = get_decoded(response, last_element)
                        whole_text += response
                        print(response)
                    elif data == "OFB":
                        response, last_element = get_decoded_OFB(received, last_element)
                        whole_text += response
            received = tcp_client.recv(1024)
        print(whole_text)
        tcp_client.close()
        break
