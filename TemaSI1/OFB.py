import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def xor(plaintext, xorer):
    return [str(a ^ b) for a, b in zip(plaintext, xorer)]


def encrypt(plaintext):
    last_encr = None
    encrypted_elements = list()
    number_of_elements_encrypted = 0
    bytes_plaintext = bytes(plaintext.encode())
    start = 0
    end = 16
    if end > len(bytes_plaintext):
        xored_array = key_encrypt(key, iv)
        encrypted_elements.append(xor_op(xored_array, bytes_plaintext))
        return encrypted_elements
    while end < len(bytes_plaintext):
        if number_of_elements_encrypted == 0:
            xored_array = key_encrypt(key, iv)
            number_of_elements_encrypted += 1
        else:
            xored_array = key_encrypt(last_encr, key)
        encr = xor_op(xored_array, bytes_plaintext[start:end])
        encrypted_elements.append(encr)
        start = end
        end += 16
        last_encr = xored_array
    end -= 16
    if end != len(bytes_plaintext):
        xored_array = key_encrypt(last_encr, key)
        encr = xor_op(xored_array, bytes_plaintext[end:len(bytes_plaintext)])
        encrypted_elements.append(encr)
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
            decr_elem.append(bytes(result))
        last_element = element
    return decr_elem


def key_encrypt_OFB(text, given_key):
    cipher = AES.new(given_key, AES.MODE_ECB)
    raw = pad(str(text).encode(), 16)
    enc = cipher.encrypt(raw)
    return base64.b64encode(enc).decode('utf-8')


def key_decrypt_OFB(text, given_key):
    enc = base64.b64decode(text)
    cipher = AES.new(given_key, AES.MODE_ECB)
    enc2 = cipher.decrypt(enc)
    return unpad(enc2, 16).decode('utf-8')
