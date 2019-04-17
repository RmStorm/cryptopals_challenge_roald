import os
import base64
import random

from cryptopals_challenge_roald.crypto_lib import AesCbcCipher, PaddingError, verify_and_remove_pkcs_7_padding

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

    def decryptor(cipher_text: bytes, initialization_vector: bytes) -> bool:
        try:
            AesCbcCipher(unknown_key, initialization_vector).decrypt(cipher_text)
            return True
        except PaddingError:
            return False
    return encryptor, decryptor


def main():
    block_size = 16
    encryptor, decryptor = get_cbc_encryptor_and_decryptor()
    cipher_text, initialization_vector = encryptor()

    unknown_bytes = bytearray(len(cipher_text))
    unscrambled_attack = initialization_vector + cipher_text
    attack_bytes = bytearray(initialization_vector + cipher_text)
    for i in reversed(range(len(cipher_text))):
        if (i+1)%16 == 0 and i+1 < len(cipher_text):
            block = int((i+1)/block_size)
            attack_bytes[-32:] = unscrambled_attack[(block)*16:(block+1)*16]
        for byte in reversed([a % 2 ** 8 for a in range(unscrambled_attack[i], unscrambled_attack[i] + 2 ** 8)]):
            attack_bytes[i] = byte
            if decryptor(attack_bytes[16:], attack_bytes[:16]):
                unknown_bytes[i] = unscrambled_attack[i] ^ byte ^ (block_size - i % block_size)
                for ii, byyte in enumerate(attack_bytes[i:-16]):
                    attack_bytes[i+ii] = byyte ^ (block_size - i % block_size) ^ (1 + block_size - i % block_size)
                break

    print(base64.b64decode(verify_and_remove_pkcs_7_padding(unknown_bytes)))


if __name__ == '__main__':
    main()
