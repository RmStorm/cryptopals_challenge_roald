import os

from cryptopals_challenge_roald.set1.set1_6_break_repeating_key_xor import estimate_key_size_for_file


def main():
    overall_minimum_distance = []
    with open(os.path.join(os.getcwd(), '..', '..', '..', 'data', 'set1_8_data'), 'r') as file_handle:
        for line_number, line in enumerate(file_handle):
            _, _, minimum_distance = estimate_key_size_for_file(bytes.fromhex(line), 16, 17, number_of_blocks=10)

            if not overall_minimum_distance or minimum_distance < overall_minimum_distance:
                overall_minimum_distance = minimum_distance
                aes_encrypted_line = line

    print(aes_encrypted_line)


if __name__ == '__main__':
    main()
