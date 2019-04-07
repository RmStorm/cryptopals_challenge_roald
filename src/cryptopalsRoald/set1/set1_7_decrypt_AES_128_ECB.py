import os
import base64

from cryptopalsRoald.crypto_lib import AesEcbCipher


def main():
    with open(os.path.join(os.getcwd(), '..', '..', '..', 'data', 'set1_7_data'), 'br') as file_handle:
        encrypted_bytes = base64.b64decode(file_handle.read())

    key = b'YELLOW SUBMARINE'
    aes_ecb_cipher = AesEcbCipher(key)

    my_text = aes_ecb_cipher.decrypt(encrypted_bytes)
    print(my_text)


if __name__ == '__main__':
    main()
