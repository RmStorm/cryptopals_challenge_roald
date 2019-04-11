import os
import base64
import heapq
from typing import Callable, Union

from cryptopals_challenge_roald.crypto_lib import AesEcbCipher, crack_ecb_encryptor

DIR_PATH = os.path.dirname(os.path.realpath(__file__))
RETRIES_FOR_MAX = 100


def get_encryptor_with_attack_bytes_in_middle():
    unknown_key = os.urandom(16)
    with open(os.path.join(DIR_PATH, '..', '..', '..', 'data', 'set2_12_data'), 'br') as file_handle:
        unknown_bytes = base64.b64decode(file_handle.read())
    aes_ecb_cipher = AesEcbCipher(unknown_key)

    def encryptor(attacker_controlled: bytes) -> bytes:
        random_prepend = os.urandom(9 + int(os.urandom(1)[0] / (2 ** 8 / 7)))
        return aes_ecb_cipher.encrypt(random_prepend + attacker_controlled + unknown_bytes)
    return encryptor


def get_block_size(encryptor: Callable[[bytes], bytes]) -> int:
    # Tune retries for max to block_size, it should be a bunch bigger than the block size I think
    cipher_lengths = []
    for attack_length in range(RETRIES_FOR_MAX):
        attack_bytes = bytes([0])*attack_length
        cipher_lengths.extend([len(encryptor(attack_bytes)) for _ in range(RETRIES_FOR_MAX)])
        two_largest = heapq.nlargest(2, set(cipher_lengths))
        if len(two_largest) == 2:
            return two_largest[0]-two_largest[1]


def get_attack_length_for_cipher_increase(encryptor: Callable[[bytes], bytes]) -> int:
    max_starting_size = max([len(encryptor(b'')) for _ in range(RETRIES_FOR_MAX)])
    attack_lengths = []
    for _ in range(RETRIES_FOR_MAX):
        for attack_length in range(RETRIES_FOR_MAX):
            attack_bytes = bytes([0]) * attack_length
            max_cur_size = max([len(encryptor(attack_bytes)) for _ in range(RETRIES_FOR_MAX)])
            if max_cur_size > max_starting_size:
                attack_lengths.append(attack_length)
                break
    assert len(set(attack_lengths)) == 1, 'Increase RETRIES_FOR_MAX to consistently hit the longest random prepend'
    return attack_lengths[0]


def crack_ecb_encryptor_with_random_prepend(encryptor: Callable[[bytes], bytes],
                                            block_size: int, attack_length: int) -> bytes:
    max_cipher_length = max([len(encryptor(bytes([0])*attack_length)) for _ in range(RETRIES_FOR_MAX)])

    def get_max_length_cipher(attack_bytes: bytes) -> bytes:
        max_length_cipher_text = encryptor(attack_bytes)
        while len(max_length_cipher_text) < max_cipher_length + block_size * 3:
            max_length_cipher_text = encryptor(attack_bytes)
        return max_length_cipher_text

    def block_getter(byte_str: bytes, block: int) -> bytes:
        return byte_str[block * block_size:(1 + block) * block_size]

    cipher_text = get_max_length_cipher(bytes([0]) * (attack_length + block_size * 3))

    number_of_blocks = int(len(cipher_text)/block_size)
    for cipher_block_index in range(number_of_blocks):
        if block_getter(cipher_text, cipher_block_index) == block_getter(cipher_text, cipher_block_index+1):
            zeros_cipher = block_getter(cipher_text, cipher_block_index)
            last_attacker_block_index = cipher_block_index+1

    zeros_with_a_one = bytearray([0])*block_size*3
    for i in reversed(range(len(zeros_with_a_one))):
        zeros_with_a_one[i] = 1
        cipher_text = get_max_length_cipher(bytes([0]) * attack_length + zeros_with_a_one)
        zeros_with_a_one[i] = 0
        if block_getter(cipher_text, last_attacker_block_index) != zeros_cipher:
            seven_zeros_ending_on_one_cipher = block_getter(cipher_text, last_attacker_block_index)
            end_of_last_attacker_block = i
            break
    secret_string_length = (len(cipher_text) - (last_attacker_block_index + 1) * block_size) - \
                           len(zeros_with_a_one[1+end_of_last_attacker_block:]) - 15

    zeros_with_a_one[end_of_last_attacker_block+1] = 1
    attack_bytes_first_part = bytes([0]) * (attack_length-1) + zeros_with_a_one[:end_of_last_attacker_block+2]

    def get_cipher_text(attack_bytes_extra: Union[bytearray, bytes]) -> bytes:
        for _ in range(RETRIES_FOR_MAX):
            cipher_text = encryptor(attack_bytes_first_part + attack_bytes_extra)
            if seven_zeros_ending_on_one_cipher == block_getter(cipher_text, last_attacker_block_index):
                return cipher_text
        raise RuntimeError(f'recognizable string was not encountered in ciphertext in {RETRIES_FOR_MAX} tries')

    return crack_ecb_encryptor(get_cipher_text, block_size, secret_string_length, last_attacker_block_index + 1)


def main():
    encryptor = get_encryptor_with_attack_bytes_in_middle()
    block_size = get_block_size(encryptor)
    attack_length = get_attack_length_for_cipher_increase(encryptor)

    print(crack_ecb_encryptor_with_random_prepend(encryptor, block_size, attack_length).decode('utf-8'))


if __name__ == '__main__':
    main()
