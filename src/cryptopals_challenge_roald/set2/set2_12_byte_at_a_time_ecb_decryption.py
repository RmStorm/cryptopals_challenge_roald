import os
import base64
from typing import Callable

from cryptopals_challenge_roald.crypto_lib import AesEcbCipher


def get_block_size(encryptor: Callable[[bytes], bytes]) -> (int, int):
    starting_size = len(encryptor(bytes()))
    block_size, i = 0, 0
    while block_size == 0:
        i = i + 1
        block_size = len(encryptor(bytes([0] * i))) - starting_size
    return block_size, starting_size - i + 1


def get_encryptor_with_input_prepend():
    unknown_key = os.urandom(16)
    with open(os.path.join(os.getcwd(), '..', '..', '..', 'data', 'set2_12_data'), 'br') as file_handle:
        unknown_bytes = base64.b64decode(file_handle.read())
    aes_ecb_cipher = AesEcbCipher(unknown_key)

    def encryptor(prepend: bytes) -> bytes:
        return aes_ecb_cipher.encrypt(prepend + unknown_bytes)
    return encryptor


def get_block_getter(block_size: int):
    def block_getter(byte_str: bytes, block: int) -> bytes:
        return byte_str[block * block_size:(1 + block) * block_size]
    return block_getter


def main():
    encryptor = get_encryptor_with_input_prepend()
    block_size, secret_string_length = get_block_size(encryptor)
    block_getter = get_block_getter(block_size)
    # It's easy to verify that ECB is used by supplying a multiple of the block size of zeros, the blocks with zeros
    # will encrypt to identical blocks in the cipher text which can be verified
    encrypted_string = encryptor(bytes([0])*block_size*2)
    assert encrypted_string[0:block_size] == encrypted_string[block_size: 2 * block_size]

    known_bytes = bytearray()
    # Create n cipher texts with 15-0 zeros prepended, these can be indexed and matched against later on
    cipher_texts = {i: encryptor(bytes([0]*(block_size - i - 1))) for i in range(block_size)}
    # The first block we will crack is all zeros with 1 unknown character
    known_block_minus_one = bytearray([0]*(block_size-1))
    for _ in range(secret_string_length):
        # Index the block that is currently being cracked
        wanted = block_getter(cipher_texts[len(known_bytes) % block_size], int((len(known_bytes))/block_size))
        for byte in range(2**8):
            # Here we only use the first block of the cipher text. The rest is considered just noise.
            cipher_text = block_getter(encryptor(known_block_minus_one + bytes([byte])), 0)
            if wanted == cipher_text:
                del known_block_minus_one[0]
                known_block_minus_one.append(byte)
                known_bytes.append(byte)
                break
    print(known_bytes)


if __name__ == '__main__':
    main()
