import socket
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


def get_encryption_type():
    encryption_type = input("Node A Choose: CBC or OFB: ")
    return encryption_type


def aes_ecb_decrypt(cypher):
    aes = AES.new(AES_data["K3"].encode("utf8"), AES.MODE_ECB)
    aes_key = aes.decrypt(cypher)
    return unpad(aes_key, 16)


def get_first_iteration_CBC(text):
    CBC_text = CBC.key_decrypt_CBC(text, AES_data['key'])
    CBC_INT = [int(x) for x in CBC_text.split("~")]
    final_string = CBC.xor(CBC_INT, AES_data['iv'])
    return "".join(letter for letter in [chr(int(x)) for x in final_string])


def get_decoded(text, last_element):
    CBC_decrypt = CBC.key_decrypt_CBC(text, AES_data['key'])
    CBC_INT = [int(x) for x in CBC_decrypt.split("~")]
    result = CBC.xor(CBC_INT, last_element.encode())
    return "".join(letter for letter in [chr(int(x)) for x in result])


def get_first_iteration_OFB(received):
    splited_response = received.decode().split("~")
    splited_response_string = [int(x) for x in splited_response]
    OFB_encrypt = OFB.key_encrypt_OFB(AES_data["iv"], AES_data["key"])
    result = OFB.xor(splited_response_string, OFB_encrypt.encode())
    return "".join(letter for letter in [chr(int(x)) for x in result])

def get_decoded_OFB(text, last_element):
    CBC_decrypt = CBC.key_decrypt_CBC(text, AES_data['key'])
    CBC_INT = [int(x) for x in CBC_decrypt.split("~")]
    result = CBC.xor(CBC_INT, last_element.encode())
    return "".join(letter for letter in [chr(int(x)) for x in result])


whole_text = ""
while True:
    data = get_encryption_type()
    input_available = False
    tcp_client.sendall(data.encode())
    received = tcp_client.recv(1024)
    AES_data['key'] = aes_ecb_decrypt(received)
    received = tcp_client.recv(1024)
    if data == "CBC":
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
                    response = get_first_iteration_CBC(received)
                    whole_text += response
                else:
                    response = received.decode().split('LAST_ELEM')
                    response = get_decoded(response[0], response[1])
                    whole_text += response
            received = tcp_client.recv(1024)
        print(whole_text)
    elif data == "OFB":
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
                    response = get_first_iteration_OFB(received)
                    whole_text += response
                else:
                    response = received.decode().split('LAST_ELEM')
                    response = get_decoded(response[0], response[1])
                    whole_text += response
            received = tcp_client.recv(1024)
        print("Whole text: ", whole_text)
tcp_client.close()
