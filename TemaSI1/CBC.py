import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


def xor(plaintext, xorer):
    return [str(a ^ b) for a, b in zip(plaintext, xorer)]


def key_encrypt_CBC(text, given_key):
    cipher = AES.new(given_key, AES.MODE_ECB)
    raw = pad(str(text).encode(), 16)
    enc = cipher.encrypt(raw)
    return base64.b64encode(enc).decode('utf-8')


def key_decrypt_CBC(text, given_key):
    enc = base64.b64decode(text)
    cipher = AES.new(given_key, AES.MODE_ECB)
    enc2 = cipher.decrypt(enc)
    return unpad(enc2, 16).decode('utf-8')
