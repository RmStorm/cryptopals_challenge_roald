import os
import base64

from cryptopalsRoald.crypto_lib import AesCbcCipher


def main():
    with open(os.path.join(os.getcwd(), '..', '..', '..', 'data', 'set2_10_data'), 'br') as file_handle:
        encrypted_bytes = base64.b64decode(file_handle.read())

    key = b'YELLOW SUBMARINE'
    aes_cbc_cipher = AesCbcCipher(key, bytes([0])*len(key))
    print(aes_cbc_cipher.decrypt(encrypted_bytes))


if __name__ == '__main__':
    main()
