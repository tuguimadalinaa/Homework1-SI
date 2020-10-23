iv = b'\x7f\xee\xad\x0bg\x8c-,\xdb\xab\x1f\xca\x02u9\x17'
key = b'\xcd\xd4\xf0#\xb5&Sh\x1f\x0bleaD.\xe7'
def xor_op(plaintext, the_xorer):
    return [a ^ b for (a, b) in zip(plaintext, the_xorer)]


def key_encrypt(xored_text, xorer):
    return [a ^ b for (a, b) in zip(xored_text, xorer)]


def key_decrypt(xored_text):
    return [a ^ b for (a, b) in zip(xored_text, key)]


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


result = encrypt("ana are mere rosii")
print("Encrypted text: ", result)
decr = decrypt(result)
string = ""
for x in decr:
    string += x.decode()
print("Decrypted text: ", string)