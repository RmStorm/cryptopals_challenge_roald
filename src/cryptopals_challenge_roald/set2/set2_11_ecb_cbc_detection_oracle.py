import os
from typing import Callable

from cryptopals_challenge_roald.crypto_lib import AesEcbCipher, AesCbcCipher, average_hamming_distance_between_blocks


def encryption_oracle(unknown_encryptor: Callable[[bytes, bytes], bytes]) -> str:
    """This function accepts a random encryption function as input argument and determines if it encrypts in ECB.

    The expected input arguments for the encryption function are: a byte_string to be encrypted and an encryption key.
    The output of the function should be an encrypted string"""
    my_bytes = b'This is 16 bytes'*30
    encrypted_bytes = unknown_encryptor(my_bytes, os.urandom(16))
    hamming_distance = average_hamming_distance_between_blocks(encrypted_bytes[32:], 16, 20)
    return 'ECB' if hamming_distance < 3 else 'Not ECB'


def encrypt_ecb_or_cbc(bytes_str: bytes, key: bytes) -> bytes:
    """This function encrypts a string in EBC or CBC mode randomly. 5-10 random bytes are added to the beginning and
    end of the input byte string. CBC mode uses a random initialization vector"""
    prepend_bytes = os.urandom(5 + int(os.urandom(1)[0] / (2 ** 8 / 6)))
    append_bytes = os.urandom(5 + int(os.urandom(1)[0] / (2 ** 8 / 6)))
    encryptable_bytes = b''.join([prepend_bytes, bytes_str, append_bytes])
    if os.urandom(1)[0] > 127:
        return AesEcbCipher(key).encrypt(encryptable_bytes)
    else:
        return AesCbcCipher(key, os.urandom(len(key))).encrypt(encryptable_bytes)


def main():
    for _ in range(20):
        print(encryption_oracle(encrypt_ecb_or_cbc))


if __name__ == '__main__':
    main()
