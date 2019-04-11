import os
import base64
from typing import Callable

from cryptopals_challenge_roald.crypto_lib import AesEcbCipher, crack_ecb_encryptor

DIR_PATH = os.path.dirname(os.path.realpath(__file__))


def get_encryptor_with_attacker_prepend():
    unknown_key = os.urandom(16)
    with open(os.path.join(DIR_PATH, '..', '..', '..', 'data', 'set2_12_data'), 'br') as file_handle:
        unknown_bytes = base64.b64decode(file_handle.read())
    aes_ecb_cipher = AesEcbCipher(unknown_key)

    def encryptor(prepend: bytes) -> bytes:
        return aes_ecb_cipher.encrypt(prepend + unknown_bytes)
    return encryptor


def get_block_size(encryptor: Callable[[bytes], bytes]) -> (int, int):
    starting_size = len(encryptor(bytes()))
    block_size, i = 0, 0
    while block_size == 0:
        i = i + 1
        block_size = len(encryptor(bytes([0] * i))) - starting_size
    # This i caused and increase in length so the previous i perfectly filled up the padding!
    return block_size, starting_size - (i-1)


def main():
    encryptor = get_encryptor_with_attacker_prepend()
    block_size, secret_string_length = get_block_size(encryptor)
    # It's easy to verify that ECB is used by supplying a multiple of the block size in zeros, the blocks with zeros
    # will encrypt to identical blocks in the cipher text which can be verified
    encrypted_string = encryptor(bytes([0])*block_size*2)
    assert encrypted_string[0:block_size] == encrypted_string[block_size: 2 * block_size]

    print(crack_ecb_encryptor(encryptor, block_size, secret_string_length, 0).decode('utf-8'))


if __name__ == '__main__':
    main()
