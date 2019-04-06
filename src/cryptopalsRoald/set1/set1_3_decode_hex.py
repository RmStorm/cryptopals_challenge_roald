from cryptopalsRoald.set1 import set1_2_hex_xor
from cryptopalsRoald.roald_codecs import HEX_MAP

ALPHABET_BYTES = b'abcdefghijklmnopqrstuvwxyz0123456789 '
ALL_BYTES = [bytes.fromhex(k1 + k2) for k1 in HEX_MAP.keys() for k2 in HEX_MAP.keys()]

def xor_against_single_char(input_bytes: bytes, decoding_char: bytes):
    return set1_2_hex_xor.bytes_xor(input_bytes, decoding_char*len(input_bytes))


def decode_byte_string_with_bytes(bytes_str: bytes, percentage: float):
    result = {}
    for byte in ALL_BYTES:
        score = 0
        decoded_bytes = xor_against_single_char(bytes_str, byte)
        for decoded_byte in decoded_bytes:
            if bytes([decoded_byte]) in ALPHABET_BYTES:
                score = score + 1
        if score > percentage * len(bytes_str):
            result[byte] = decoded_bytes
    return result

if __name__ == '__main__':
    bytes_str = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    for k, v in decode_byte_string_with_bytes(bytes_str, .8).items():
        print(f'decoding byte: {k}, decoded string:\n{v}')

