import base64

from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad


iv = b'\x7f\xee\xad\x0bg\x8c-,\xdb\xab\x1f\xca\x02u9\x17'
key = b'\xcd\xd4\xf0#\xb5&Sh\x1f\x0bleaD.\xe7'

def xor_op(plaintext, the_xorer):
    return [a ^ b for a,b in zip(plaintext, the_xorer)]


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


def encrypt(plaintext):
    encrypted_elements = list()
    number_of_elements_encrypted = 0
    bytes_plaintext = bytes(plaintext.encode())
    start = 0
    end = 16
    if end > len(bytes_plaintext):
        xored = xor_op(bytes_plaintext[start:len(bytes_plaintext)], iv)
        encr = key_encrypt(xored)
        encrypted_elements.append(encr)
        return encrypted_elements
    while end != len(bytes_plaintext):
        if number_of_elements_encrypted == 0:
            xored_array = xor_op(bytes_plaintext[start:end], iv)
            number_of_elements_encrypted += 1
        else:
            print(encrypted_elements[len(encrypted_elements) - 1])
            xored_array = xor_op(bytes_plaintext[start:end], bytes_list)
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
        new_decr = [int(x) for x in decr]
        if nr_of_decr == 0:
            result = xor_op(new_decr, iv)
            decr_elem.append(result)
            nr_of_decr += 1
        else:
            result = xor_op(new_decr, last_element)
            decr_elem.append(result)
        last_element = element
    return decr_elem


result = encrypt("ana")
print("Encrypted text: ", result)
decr = decrypt(result)
string = ""
for x in decr[0]:
    string += chr(x)
print("Decrypted text: ", string)

