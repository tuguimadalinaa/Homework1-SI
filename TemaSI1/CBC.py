import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import os
import numpy as np

# https://stackoverflow.com/questions/29408173/byte-operations-xor-in-python
# iv = Crypto.Random.get_random_bytes(AES.block_size)


iv = b'\x7f\xee\xad\x0bg\x8c-,\xdb\xab\x1f\xca\x02u9\x17'
key = b'\xcd\xd4\xf0#\xb5&Sh\x1f\x0bleaD.\xe7'


def xor_op(plaintext, the_xorer):
    return [a ^ b for a, b in zip(plaintext, the_xorer)]


def key_encrypt(message):
    print("Inainte de encrypt: ", message)
    message = ''.join(map(str, message))
    raw = pad(message.encode(), 16)
    cipher = AES.new(key, AES.MODE_ECB)
    enc = cipher.encrypt(raw)
    print("Enc:", enc)
    return enc


def key_decrypt(enc):
    raw = pad(enc, 16)
    cipher = AES.new(key, AES.MODE_ECB)
    dec = cipher.decrypt(raw)
    print("Dec: ", dec)
    return dec


def encrypt(plaintext):
    encrypted_elements = list()
    number_of_elements_encrypted = 0
    bytes_plaintext = bytes(plaintext.encode())
    start = 0
    end = 16
    if end > len(bytes_plaintext):
        xored = xor_op(bytes_plaintext[start:len(bytes_plaintext)], iv)
        encrypted_elements.append(key_encrypt(xored))
        return encrypted_elements
    while end > len(bytes_plaintext):
        if number_of_elements_encrypted == 0:
            xored_array = xor_op(bytes_plaintext[start:end], iv)
            number_of_elements_encrypted += 1
        else:
            xored_array = xor_op(bytes_plaintext[start:end], encrypted_elements[len(encrypted_elements) - 1])
        encr = key_encrypt(xored_array)
        encrypted_elements.append(encr)
        start = end
        end += 16
    end -= 16

    if end != len(bytes_plaintext):
        xored_array = xor_op(bytes_plaintext[end:len(bytes_plaintext)], encrypted_elements[len(encrypted_elements) - 1])
        encrypted_elements.append(key_encrypt(xored_array))
    return encrypted_elements


def decrypt(array_cipher):
    decr_elem = []
    nr_of_decr = 0
    last_element = None
    for element in array_cipher:
        print("Elementul trimis la decriptat: ", element)
        decr = key_decrypt(element)
        print("Elementul decriptat: ", decr)
        if nr_of_decr == 0:
            result = xor_op([30, 128, 204], iv)
            decr_elem.append(result)
            nr_of_decr += 1
        else:
            result = xor_op(decr, last_element)
            decr_elem.append(result)
        last_element = element
    return decr_elem


result = encrypt("ana")
# print("Encrypted text: ", len(result[0]))
decr = decrypt(result)
string= ""
print(decr[0])
for x in decr[0]:
    string += chr(x)
print("Decrypted text: ", string)

# aes = AES.new(key, AES.MODE_CBC, iv)
# # list = "".join(str(x) for x in xored_text)
# # return aes.decrypt(pad(list.encode(), AES.block_size))
# return aes.decrypt(pad(xored_text, AES.block_size))
# https://stackoverflow.com/questions/51884553/aes-ecb-encrypting-in-python
