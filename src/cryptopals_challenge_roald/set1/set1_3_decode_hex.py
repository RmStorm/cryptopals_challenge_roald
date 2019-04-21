from itertools import cycle

from cryptopals_challenge_roald.crypto_lib import bytes_xor, ALPHABET_BYTES


def find_likely_xor_byte_with_alphabet(bytes_str: bytes, percentage: float):
    result = {}
    for byte in [bytes([i]) for i in range(2**8)]:
        score = 0
        decoded_bytes = bytes_xor(bytes_str, cycle(byte))
        for decoded_byte in decoded_bytes:
            if bytes([decoded_byte]) in ALPHABET_BYTES:
                score = score + 1
        if score > percentage * len(bytes_str):
            result[byte] = decoded_bytes
    return result


def main():
    bytes_str = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    for k, v in find_likely_xor_byte_with_alphabet(bytes_str, .99).items():
        print(f'decoding byte: {k}, decoded string:\n{v}')


if __name__ == '__main__':
    main()
