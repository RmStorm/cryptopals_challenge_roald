import os
import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


class AES_ECB_Cipher(object):
    def __init__(self, key):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

    def encrypt(self, byte_str: bytes):
        return self.encryptor.update(byte_str)

    def decrypt(self, byte_str: bytes):
        return self.decryptor.update(byte_str)

def main():
    with open(os.path.join(os.getcwd(), '..', '..', '..', 'data', 'set1_7_data'), 'br') as file_handle:
        encrypted_bytes = base64.b64decode(file_handle.read())

    key = b'YELLOW SUBMARINE'
    aes_ecb_cipher = AES_ECB_Cipher(key)

    my_text = aes_ecb_cipher.decrypt(encrypted_bytes)
    print(my_text)


if __name__ == '__main__':
    main()
