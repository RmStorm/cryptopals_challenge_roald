import os

from cryptopals_challenge_roald.crypto_lib import average_hamming_distance_between_blocks


def main():
    overall_minimum_distance = []
    with open(os.path.join(os.getcwd(), '..', '..', '..', 'data', 'set1_8_data'), 'r') as file_handle:
        for line_number, line in enumerate(file_handle):
            hamming_distance = average_hamming_distance_between_blocks(bytes.fromhex(line), 16, 10)

            if not overall_minimum_distance or hamming_distance < overall_minimum_distance:
                overall_minimum_distance = hamming_distance
                aes_encrypted_line = line

    print(aes_encrypted_line)


if __name__ == '__main__':
    main()
