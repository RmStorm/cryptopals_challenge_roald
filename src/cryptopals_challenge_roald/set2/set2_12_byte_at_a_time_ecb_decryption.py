import os
import base64

from cryptopals_challenge_roald.crypto_lib import AesEcbCipher
from cryptopals_challenge_roald.set2.set2_11_ecb_cbc_detection_oracle import encryption_oracle


class ecb_encrtyptor_with_unknown_key(object):
    def __init__(self):
        self.key = os.urandom(16)

def main():
    unknown_key = os.urandom(16)
    with open(os.path.join(os.getcwd(), '..', '..', '..', 'data', 'set2_12_data'), 'br') as file_handle:
        my_bytes = base64.b64decode(file_handle.read())

    aes_ecb_cipher = AesEcbCipher(unknown_key)
    my_encryption_dict = {aes_ecb_cipher.encrypt(bytes([*[0]*(len(unknown_key)-1), i])): bytes([i])
                          for i in range(2 ** 8)}
    solution = b''
    for i in my_bytes:
        solution = solution + my_encryption_dict[aes_ecb_cipher.encrypt(bytes([*[0] * (len(unknown_key) - 1), i]))]
    print(solution.decode('utf-8'))


if __name__ == '__main__':
    main()
