from typing import Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def bytes_xor(byte_str1: bytes, byte_str2: Union[bytes, iter]) -> bytes:
    return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))


def apply_pkcs_7_padding(input_bytes: bytes, block_length: int) -> bytes:
    padding_length = block_length - len(input_bytes)%block_length
    return input_bytes + bytes([padding_length])*padding_length


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
