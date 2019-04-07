from typing import Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def bytes_xor(byte_str1: bytes, byte_str2: Union[bytes, iter]) -> bytes:
    return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))


def apply_pkcs_7_padding(input_bytes: bytes, block_length: int) -> bytes:
    padding_length = (block_length - len(input_bytes)%block_length) if len(input_bytes)%block_length != 0 else 0
    return input_bytes + bytes([padding_length])*padding_length


class AesEcbCipher(object):
    def __init__(self, key):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()

    def encrypt(self, byte_str: bytes):
        return self.encryptor.update(byte_str)

    def decrypt(self, byte_str: bytes):
        return self.decryptor.update(byte_str)


class AesCbcCipher(object):
    def __init__(self, key, initialization_vector):
        assert len(key) == len(initialization_vector), 'Initialization vector and key must be of the same length'
        self.initialization_vector = initialization_vector
        self.aes_ecb_cipher = AesEcbCipher(key)
        self.key_size = len(key)

    def encrypt(self, byte_str: bytes):
        encryptable_bytes = apply_pkcs_7_padding(byte_str, self.key_size)
        encrypted_blocks = [self.initialization_vector]
        for i in range(int(len(encryptable_bytes)/self.key_size)):
            xorred_block = bytes_xor(encrypted_blocks[i], encryptable_bytes[i*self.key_size:(i+1)*self.key_size])
            encrypted_blocks.append(self.aes_ecb_cipher.encryptor.update(xorred_block))
        return b''.join(encrypted_blocks[1:])

    def decrypt(self, byte_str: bytes):
        assert len(byte_str) % self.key_size == 0, 'Encrypted message is not a multiple of your key_size'
        decrypted_blocks = []
        prev_block = self.initialization_vector
        for i in range(int(len(byte_str) / self.key_size)):
            this_block = byte_str[i * self.key_size:(i + 1) * self.key_size]
            decrypted_blocks.append(bytes_xor(prev_block, self.aes_ecb_cipher.decryptor.update(this_block)))
            prev_block = this_block
        return b''.join(decrypted_blocks)
