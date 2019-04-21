import os
import base64
import itertools

from cryptopals_challenge_roald.set1.set1_3_decode_hex import find_likely_xor_byte_with_alphabet
from cryptopals_challenge_roald.crypto_lib import AesCtrCipher, bytes_xor

DIR_PATH = os.path.dirname(os.path.realpath(__file__))


def encrypt_with_same_nonce():
    with open(os.path.join(DIR_PATH, '..', '..', '..', 'data', 'set3_19_data'), 'br') as file_handle:
        data_lines = file_handle.read().splitlines()

    unknown_key = os.urandom(16)
    aes_ctr_cipher = AesCtrCipher(unknown_key, 0)

    encrypted_lines = [aes_ctr_cipher.encrypt(base64.b64decode(data_line)) for data_line in data_lines]
    return encrypted_lines


def main():
    cipher_texts = encrypt_with_same_nonce()
    possible_xor_bytes = bytearray()
    possible_xor_byte_dicts = []
    for aligned_bytes in itertools.zip_longest(*cipher_texts):
        print(len(list(b for b in aligned_bytes if b)))
        alphabet_bytes = {}
        percentage = .99
        while len(alphabet_bytes) < 2:
            alphabet_bytes = find_likely_xor_byte_with_alphabet(list(b for b in aligned_bytes if b), percentage)
            percentage -= .01
        possible_xor_byte_dicts.append(alphabet_bytes)
        possible_xor_bytes.append(next(iter(possible_xor_byte_dicts[-1].keys()))[0])

    for i in range(len(possible_xor_bytes)):
        for byte in possible_xor_byte_dicts[i].keys():
            possible_xor_bytes[i] = byte[0]
            for cipher_text in cipher_texts:
                print(bytes_xor(cipher_text, possible_xor_bytes))
            print(' ', ''.join(str(i%10) for i in range(len(possible_xor_bytes))))
            good = input(f'Do you think byte {i} is correct? enter y or n')
            if good == 'y':
                break
    print(possible_xor_bytes)


if __name__ == '__main__':
    main()
