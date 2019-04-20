import os
import base64
import random

from cryptopals_challenge_roald.crypto_lib import AesCbcCipher, PaddingError, verify_and_remove_pkcs_7_padding

DIR_PATH = os.path.dirname(os.path.realpath(__file__))


def get_cbc_encryptor_and_decryptor_of_set_17_data(choose_line=None, block_size=16):
    with open(os.path.join(DIR_PATH, '..', '..', '..', 'data', 'set3_17_data'), 'br') as file_handle:
        data_lines = file_handle.read().splitlines()
    my_data_line = data_lines[choose_line] if choose_line else random.choice(data_lines)
    unknown_key = os.urandom(block_size)
    initialization_vector = os.urandom(block_size)
    aes_cbc_cipher = AesCbcCipher(unknown_key, initialization_vector)

    def encryptor() -> [bytes, bytes]:
        return aes_cbc_cipher.encrypt(my_data_line), initialization_vector

    def decryptor(cipher_text: bytes, attacker_initialization_vector: bytes) -> bool:
        return AesCbcCipher(unknown_key, attacker_initialization_vector).decrypt(cipher_text)
    return encryptor, decryptor


def cbc_padding_oracle(decryptor):
    def wrapped_decryptor(*args, **kwargs):
        try:
            decryptor(*args, **kwargs)
            return True
        except PaddingError:
            return False
    return wrapped_decryptor


def cbc_padding_oracle_attack(encryptor, decryptor, block_size=16):
    cipher_text, initialization_vector = encryptor()
    padding_oracle = cbc_padding_oracle(decryptor)

    unknown_bytes = bytearray(len(cipher_text))
    unscrambled_attack = initialization_vector + cipher_text
    attack_bytes = bytearray(initialization_vector + cipher_text)
    for i in reversed(range(len(cipher_text))):
        if (i + 1) % block_size == 0 and i + 1 < len(cipher_text):
            block = int((i+1)/block_size)
            attack_bytes[-(2*block_size):] = unscrambled_attack[block*block_size:(block+1)*block_size]
        for byte in reversed([a % 2 ** 8 for a in range(unscrambled_attack[i], unscrambled_attack[i] + 2 ** 8)]):
            attack_bytes[i] = byte
            if padding_oracle(attack_bytes[block_size:], attack_bytes[:block_size]):
                unknown_bytes[i] = unscrambled_attack[i] ^ byte ^ (block_size - i % block_size)
                for ii, byyte in enumerate(attack_bytes[i:-block_size]):
                    attack_bytes[i+ii] = byyte ^ (block_size - i % block_size) ^ (1 + block_size - i % block_size)
                break

    return base64.b64decode(verify_and_remove_pkcs_7_padding(unknown_bytes))


def main():
    print(cbc_padding_oracle_attack(*get_cbc_encryptor_and_decryptor_of_set_17_data()))


if __name__ == '__main__':
    main()
