from itertools import cycle

from cryptopalsRoald.crypto_lib import bytes_xor
from cryptopalsRoald.roald_codecs import HEX_MAP

ALPHABET_BYTES = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789' "
ALL_BYTES = [bytes.fromhex(k1 + k2) for k1 in HEX_MAP.keys() for k2 in HEX_MAP.keys()]


def decode_byte_string_with_bytes(bytes_str: bytes, percentage: float):
    result = {}
    for byte in ALL_BYTES:
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
    for k, v in decode_byte_string_with_bytes(bytes_str, .99).items():
        print(f'decoding byte: {k}, decoded string:\n{v}')


if __name__ == '__main__':
    main()
