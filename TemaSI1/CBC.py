from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

# https://stackoverflow.com/questions/29408173/byte-operations-xor-in-python
# iv = Crypto.Random.get_random_bytes(AES.block_size)


iv = b'\x7f\xee\xad\x0bg\x8c-,\xdb\xab\x1f\xca\x02u9\x17'
key = b'\xcd\xd4\xf0#\xb5&Sh\x1f\x0bleaD.\xe7'


def xor_op(plaintext, the_xorer):
    return [a ^ b for (a, b) in zip(plaintext, the_xorer)]


def key_encrypt(xored_text):
    return [a ^ b for (a, b) in zip(xored_text, key)]


def key_decrypt(xored_text):
    return [a ^ b for (a, b) in zip(xored_text, key)]


def encrypt(plaintext):
    encrypted_elements = list()
    number_of_elements_encrypted = 0
    bytes_plaintext = bytes(plaintext.encode())
    start = 0
    end = 16
    if end > len(bytes_plaintext):
        xored_array = xor_op(bytes_plaintext[start:len(bytes_plaintext)], iv)
        encrypted_elements.append(key_encrypt(xored_array))
        return encrypted_elements
    while end < len(bytes_plaintext):
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
        decr = key_decrypt(element)
        if nr_of_decr == 0:
            result = xor_op(decr, iv)
            decr_elem.append(bytes(result))
            nr_of_decr += 1
        else:
            result = xor_op(decr, last_element)
            print(bytes(result))
            decr_elem.append(bytes(result))
        last_element = element
    return decr_elem


result = encrypt("ana")
decr = decrypt(result)
string = ""
for x in decr:
    string += x.decode()
print(string)

# aes = AES.new(key, AES.MODE_CBC, iv)
# # list = "".join(str(x) for x in xored_text)
# # return aes.decrypt(pad(list.encode(), AES.block_size))
# return aes.decrypt(pad(xored_text, AES.block_size))
