import os
from cryptopals_challenge_roald.set1.set1_3_decode_hex import decode_byte_string_with_bytes


def main():
    print(os.getcwd())
    with open(os.path.join(os.getcwd(), '..', '..', '..', 'data', 'set1_4_data'), 'r') as file_handle:
        for line_number, line in enumerate(file_handle):
            result = decode_byte_string_with_bytes(bytes.fromhex(line), .95)
            if result:
                print(f'line_number: {line_number}, line: {line}')
                print(result)
                break


if __name__ == '__main__':
    main()
