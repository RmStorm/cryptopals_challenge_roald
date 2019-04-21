import os
import base64
from itertools import cycle


from cryptopals_challenge_roald.crypto_lib import average_hamming_distance_between_blocks
from cryptopals_challenge_roald.crypto_lib import bytes_xor
from cryptopals_challenge_roald.set1.set1_3_decode_hex import find_likely_xor_byte_with_alphabet


def estimate_key_size_for_file(encrypted_bytes: bytes, start_key_size: int, end_key_size: int,
                               number_of_blocks: int = 3):
    """When text is encrypted using the same key over and over detectable patterns occur in the encrypted bytes. Since
    meaningful text is not random the encrypted strings will become similar when split up with the same length as the
    key used to encrypt to text

    This file returns: probable_key_size, distances, minimum_distance
    usage: key_size, _, _ = estimate_key_size_for_file(encrypted_bytes, 10, 40)
    """
    distances = {}
    for key_size in range(start_key_size, end_key_size):
        distances[average_hamming_distance_between_blocks(encrypted_bytes, key_size, number_of_blocks)] = key_size
    return distances[min(distances.keys())], distances, min(distances.keys())


def break_key_for_key_length(encrypted_bytes: bytes, key_size: int) -> bytes:
    solved = {group: False for group in range(key_size)}
    threshold = .99
    while any(val is False for val in solved.values()) and threshold > 0:
        for group in range(key_size):
            if not solved[group]:
                for k, v in find_likely_xor_byte_with_alphabet(encrypted_bytes[group::key_size], threshold).items():
                    solved[group] = k
        threshold = threshold - .04
        print(threshold)
    return b''.join(solved.values())


def main():
    with open(os.path.join(os.getcwd(), '..', '..', '..', 'data', 'set1_6_data'), 'br') as file_handle:
        encrypted_bytes = base64.b64decode(file_handle.read())

    key_size, _, _ = estimate_key_size_for_file(encrypted_bytes, 10, 40)
    possible_key = break_key_for_key_length(encrypted_bytes, key_size)
    print(bytes_xor(encrypted_bytes, cycle(possible_key)).decode('utf-8'))


if __name__ == '__main__':
    main()
