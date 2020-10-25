import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad

iv = b'\x7f\xee\xad\x0bg\x8c-,\xdb\xab\x1f\xca\x02u9\x17'
key = b'\xcd\xd4\xf0#\xb5&Sh\x1f\x0bleaD.\xe7'


def xor(plaintext, xorer):
    return [str(a ^ b) for a, b in zip(plaintext, xorer)]


def key_encrypt(message):
    print("Inainte de encrypt: ", message)
    encrp_array = []
    for m in message:
        cipher = AES.new(key, AES.MODE_ECB)
        raw = pad(str(m).encode(), 16)
        enc = cipher.encrypt(raw)
        encrp_array.append(base64.b64encode(enc).decode('utf-8'))
    return encrp_array


def key_decrypt(enc):
    encrp_array = []
    print("A ajuns la decriptat:", enc)
    for m in enc:
        enc = base64.b64decode(m)
        cipher = AES.new(key, AES.MODE_ECB)
        enc2 = cipher.decrypt(enc)
        encrp_array.append(unpad(enc2, 16).decode('utf-8'))
    return encrp_array


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

