import os
import base64
from itertools import cycle

from cryptopalsRoald.roald_codecs import HEX_TO_BIT
from cryptopalsRoald.crypto_lib import bytes_xor
from cryptopalsRoald.set1.set1_3_decode_hex import decode_byte_string_with_bytes


def compute_hamming_distance(bytes_str1, bytes_str2) -> int:
    return sum(int(a) for item in bytes_xor(bytes_str1, bytes_str2).hex() for a in HEX_TO_BIT[item])


def estimate_key_size_for_file(encrypted_bytes: bytes, start_key_size: int, end_key_size: int,
                               number_of_blocks: int = 3):
    """
    When bytes are encrypted using XOR their results tend to have a smaller hamming distance. The Hamming distance is
    easy to compute between several blocks of bytes. To get a more informative metric the Hamming distance should be
    normalized by the possible key_size

    This file returns: probable_key, distances, minimum_distance
    usage: key_size, _, _ = estimate_key_size_for_file(encrypted_bytes, 10, 40)
    """
    distances = {}
    for key_size in range(start_key_size, end_key_size):
        blocks = [encrypted_bytes[i*key_size: (i+1)*key_size] for i in range(number_of_blocks)]
        dists = [compute_hamming_distance(bytes_str1, bytes_str2) for bytes_str1 in blocks for bytes_str2 in blocks]
        distances[sum(dists) / float(key_size * len(dists))] = key_size
    return distances[min(distances.keys())], distances, min(distances.keys())


def break_key_for_key_length(encrypted_bytes: bytes, key_size: int) -> bytes:
    solved = {group:False for group in range(key_size)}
    threshold = .99
    while any(val is False for val in solved.values()) and threshold > 0:
        for group in range(key_size):
            if not solved[group]:
                for k, v in decode_byte_string_with_bytes(encrypted_bytes[group::key_size], threshold).items():
                    solved[group] = k
        threshold = threshold -.04
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
