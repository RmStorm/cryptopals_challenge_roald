import os
import random

from cryptopals_challenge_roald.crypto_lib import AesCbcCipher, PaddingError

DIR_PATH = os.path.dirname(os.path.realpath(__file__))


def get_cbc_encryptor_and_decryptor():
    with open(os.path.join(DIR_PATH, '..', '..', '..', 'data', 'set3_17_data'), 'br') as file_handle:
        data_lines = file_handle.read().splitlines()
    my_data_line = random.choice(data_lines)
    unknown_key = os.urandom(16)
    initialization_vector = os.urandom(16)
    aes_cbc_cipher = AesCbcCipher(unknown_key, initialization_vector)

    def encryptor() -> [bytes, bytes]:
        return aes_cbc_cipher.encrypt(my_data_line), initialization_vector

    def decryptor(cipher_text: bytes) -> bool:
        print(cipher_text)
        try:
            aes_cbc_cipher.decrypt(cipher_text)
            return True
        except PaddingError:
            return False
    return encryptor, decryptor


def main():
    encryptor, decryptor = get_cbc_encryptor_and_decryptor()
    cipher_text, initialization_vector = encryptor()
    print(cipher_text, initialization_vector)
    assert decryptor(cipher_text)
    assert not decryptor(cipher_text[:-16])


if __name__ == '__main__':
    main()
