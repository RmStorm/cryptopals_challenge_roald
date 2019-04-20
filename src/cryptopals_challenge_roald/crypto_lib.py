import struct
from typing import Union

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptopals_challenge_roald.roald_codecs import HEX_TO_BIT

class CryptoPalsLibError(Exception):
    pass

class PaddingError(CryptoPalsLibError):
    pass


def apply_pkcs_7_padding(input_bytes: bytes, block_size: int) -> bytes:
    padding_length = block_size - (len(input_bytes) % block_size)
    return input_bytes + bytes([padding_length])*padding_length


def verify_and_remove_pkcs_7_padding(input_bytes: Union[bytes, bytearray]):
    final_pad = input_bytes[-1]
    if all(pad == final_pad for pad in input_bytes[-int(final_pad):]):
        return input_bytes[:-int(final_pad)]
    else:
        raise PaddingError('Invalid padding detected')


def bytes_xor(byte_str1: bytes, byte_str2: Union[bytes, iter]) -> bytes:
    return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))


def compute_hamming_distance(bytes_str1, bytes_str2) -> int:
    return sum(int(a) for item in bytes_xor(bytes_str1, bytes_str2).hex() for a in HEX_TO_BIT[item])


def average_hamming_distance_between_blocks(encrypted_bytes: bytes, key_size: int, number_of_blocks: int) -> float:
    blocks = [encrypted_bytes[i*key_size: (i+1)*key_size] for i in range(number_of_blocks)]
    dists = [compute_hamming_distance(bytes_str1, bytes_str2) for bytes_str1 in blocks for bytes_str2 in blocks]
    return sum(dists) / float(key_size * len(dists))


class AesEcbCipher(object):
    def __init__(self, key):
        backend = default_backend()
        cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
        self.encryptor = cipher.encryptor()
        self.decryptor = cipher.decryptor()
        self.key_size = len(key)

    def encrypt(self, byte_str: bytes):
        return self.encryptor.update(apply_pkcs_7_padding(byte_str, self.key_size))

    def decrypt(self, byte_str: bytes):
        return verify_and_remove_pkcs_7_padding(self.decryptor.update(byte_str))


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
        return verify_and_remove_pkcs_7_padding(b''.join(decrypted_blocks))


class AesCtrCipher(object):
    def __init__(self, key, nonce):
        self.aes_ecb_cipher = AesEcbCipher(key)
        self.key_size = len(key)
        self.nonce = nonce

    def encrypt(self, byte_str: bytes):
        encrypted_bytes = bytearray()
        for i, byte in enumerate(byte_str):
            if i%16 == 0:
                key_stream = self.aes_ecb_cipher.encryptor.update(self.nonce + struct.pack('<Q', int(i/16)))
            encrypted_bytes.append(byte ^ key_stream[i % 16])
        return encrypted_bytes


def crack_ecb_encryptor(encryptor, block_size, secret_string_length, start_block):
    """This cracks ECB"""
    def block_getter(byte_str: bytes, block: int) -> bytes:
        return byte_str[block * block_size:(1 + block) * block_size]

    known_bytes = bytearray()
    # Create n cipher texts with 15-0 zeros prepended, these can be indexed and matched against later on
    cipher_texts = {i: encryptor(bytes([0]*(block_size - i - 1))) for i in range(block_size)}
    # The first block we will crack is all zeros with 1 unknown character
    known_block_minus_one = bytearray([0]*(block_size-1))
    while len(known_bytes) != secret_string_length:
        # Get the block that is currently being cracked
        next_block = start_block + int((len(known_bytes))/block_size)
        wanted = block_getter(cipher_texts[len(known_bytes) % block_size], next_block)
        for byte in range(2**8):
            # Here we only use the first block of the cipher text. The rest can be considered noise.
            cipher_text = block_getter(encryptor(known_block_minus_one + bytes([byte])), start_block)
            if wanted == cipher_text:
                known_block_minus_one = known_block_minus_one[1:] + bytearray([byte])
                known_bytes.append(byte)
                break
    return known_bytes
