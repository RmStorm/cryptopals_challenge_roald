import os
import base64
import itertools

from colorama import Fore, Style

from cryptopals_challenge_roald.set1.set1_3_decode_hex import find_likely_xor_byte_with_score_alphabet
from cryptopals_challenge_roald.crypto_lib import AesCtrCipher, bytes_xor

DIR_PATH = os.path.dirname(os.path.realpath(__file__))


def encrypt_with_same_nonce(data_file):
    with open(os.path.join(DIR_PATH, '..', '..', '..', 'data', data_file), 'br') as file_handle:
        data_lines = file_handle.read().splitlines()

    unknown_key = os.urandom(16)
    aes_ctr_cipher = AesCtrCipher(unknown_key, 0)

    encrypted_lines = [aes_ctr_cipher.encrypt(base64.b64decode(data_line)) for data_line in data_lines]
    return encrypted_lines


def print_cipher_text_with_colored_n(cipher_texts, possible_xor_bytes, n=1000):
    for cipher_text in cipher_texts:
        guess = bytes_xor(cipher_text, possible_xor_bytes).decode("UTF-8")
        if n < len(guess):
            print(f'{guess[0:n]}{Fore.GREEN}{(guess[n])}{Style.RESET_ALL}{guess[n+1:]}')
        else:
            print(guess)


def print_current_options(possible_xor_byte_dict, current_byte):
    print(f"\n These are the options for these positions")
    for k, v in possible_xor_byte_dict.items():
        if k == current_byte:
            print(f'{Fore.GREEN}{v}{Style.RESET_ALL}')
        else:
            print(v)


def get_initial_likely_bytes(cipher_texts, truncated=False):
    possible_xor_bytes = bytearray()
    possible_xor_byte_dicts = []
    byte_iterator = zip(*cipher_texts) if truncated else itertools.zip_longest(*cipher_texts)
    for aligned_bytes in byte_iterator:
        actual_aligned_bytes = bytearray([b for b in aligned_bytes if b])
        print(f'There are {len(actual_aligned_bytes)} valid bytes at this N')
        alphabet_bytes = {}
        percentage = .99
        while len(alphabet_bytes) < 1:
            alphabet_bytes = find_likely_xor_byte_with_score_alphabet(actual_aligned_bytes, percentage)
            percentage -= .005
        possible_xor_byte_dicts.append(alphabet_bytes)
        possible_xor_bytes.append(next(iter(possible_xor_byte_dicts[-1].keys()))[0])
    return possible_xor_byte_dicts, possible_xor_bytes


def main():
    cipher_texts = encrypt_with_same_nonce('set3_19_data')
    possible_xor_byte_dicts, possible_xor_bytes = get_initial_likely_bytes(cipher_texts)
    for i in range(len(possible_xor_bytes)):
        for byte in itertools.cycle(possible_xor_byte_dicts[i].keys()):
            possible_xor_bytes[i] = byte[0]
            print_cipher_text_with_colored_n(cipher_texts, possible_xor_bytes, i)
            print_current_options(possible_xor_byte_dicts[i], byte)
            good = input(f'Do you think byte {i} is correct? enter y or n')
            if good == 'y':
                break
    print(possible_xor_bytes)


if __name__ == '__main__':
    main()
