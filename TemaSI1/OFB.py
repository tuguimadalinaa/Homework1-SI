import base64
import time

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def xor(plaintext, xorer):
    return bytes([a ^ b for a, b in zip(plaintext, xorer)])


def key_encrypt_OFB(text, given_key):
    cipher = AES.new(given_key, AES.MODE_ECB)
    time.sleep(1)
    if len(text) < 16:
        text = pad(text, 16)
    enc = cipher.encrypt(text)
    return enc


def key_decrypt_OFB(text, given_key):
    time.sleep(1)
    cipher = AES.new(given_key, AES.MODE_ECB)
    enc2 = cipher.decrypt(text)
    return unpad(enc2, 16)
