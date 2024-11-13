import json
import base64
from shutil import which

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from base64 import b64encode, b64decode
from Crypto.Util.Padding import pad, unpad

def encrypt_json(_json, key, iv):

    cipher = AES.new(key, AES.MODE_CBC, iv)

    padded_data = pad(_json.encode(), AES.block_size)

    cipher_text = cipher.encrypt(padded_data)

    encrypted_json = b64encode(cipher_text).decode('utf-8')

    with open("000849456EncryptedOrder.txt", "w") as file:
        file.writelines(["Chris's Encryption App V1.0\n", encrypted_json])

    return encrypted_json

def decrypt_json(encrypted_data, key, iv):
    data = base64.b64decode(encrypted_data)

    cipher = AES.new(key, AES.MODE_CBC, iv)

    decrypted_data = unpad(cipher.decrypt(data), AES.block_size).decode('utf-8')

    return decrypted_data



if __name__ == "__main__":

    with open("000849456Order6.json", "r") as json_file:
        json_data = json_file.read()

    original_data = json_data
    with open("SSDF23AESKeyIV.txt", "r") as key_file:
        key_data = key_file.readlines()

    b64_key = key_data[1].strip("\\n")
    b64_iv = key_data[2].strip("\\n")

    _key = b64decode(b64_key)
    _iv = b64decode(b64_iv)

    _encrypted_json = encrypt_json(json_data, _key, _iv)
    _decrypted_data = decrypt_json(_encrypted_json, _key, _iv)

    if _decrypted_data == original_data:
        print("\nOriginal data matches the encrypted then decrypted data!")
    else: print("Original data does not match encrypted then decrypted data :(")