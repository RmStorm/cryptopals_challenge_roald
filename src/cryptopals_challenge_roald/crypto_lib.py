from typing import Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptopals_challenge_roald.roald_codecs import HEX_TO_BIT


def bytes_xor(byte_str1: bytes, byte_str2: Union[bytes, iter]) -> bytes:
    return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))


def compute_hamming_distance(bytes_str1, bytes_str2) -> int:
    return sum(int(a) for item in bytes_xor(bytes_str1, bytes_str2).hex() for a in HEX_TO_BIT[item])


def average_hamming_distance_between_blocks(encrypted_bytes: bytes, key_size: int, number_of_blocks: int) -> float:
    blocks = [encrypted_bytes[i*key_size: (i+1)*key_size] for i in range(number_of_blocks)]
    dists = [compute_hamming_distance(bytes_str1, bytes_str2) for bytes_str1 in blocks for bytes_str2 in blocks]
    return sum(dists) / float(key_size * len(dists))


def apply_pkcs_7_padding(input_bytes: bytes, block_length: int) -> bytes:
    modulo_length = len(input_bytes) % block_length
    padding_length = (block_length - modulo_length) if modulo_length != 0 else 0
    return input_bytes + bytes([padding_length])*padding_length


class AesEcbCipher(object):
    def __init__(self, key):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()
        self.key_size = len(key)

    def encrypt(self, byte_str: bytes):
        encryptable_bytes = apply_pkcs_7_padding(byte_str, self.key_size)
        return self.encryptor.update(encryptable_bytes)

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
