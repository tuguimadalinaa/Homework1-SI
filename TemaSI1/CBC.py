import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

def remove_pad(x):
    new_number = x
    for number in range(len(x)):
        if number == 0:
            if x[number] != 48:
                break
        if x[number] != 48:
            new_number = x[number:]
            break
    return new_number


def xor(plaintext, xorer):
    return bytes([a ^ b for a, b in zip(plaintext, xorer)])


def key_encrypt_CBC(text, given_key):
    time.sleep(1)
    if len(text) < 16:
        text = text.zfill(16)
    cipher = AES.new(given_key, AES.MODE_ECB)
    enc = cipher.encrypt(text)
    return enc


def key_decrypt_CBC(text, given_key):
    time.sleep(1)
    cipher = AES.new(given_key, AES.MODE_ECB)
    enc2 = cipher.decrypt(text)
    return remove_pad(enc2)
