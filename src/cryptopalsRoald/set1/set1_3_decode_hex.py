from cryptopalsRoald.set1 import set1_2_hex_xor
from cryptopalsRoald.roald_codecs import HEX_MAP


def xor_against_single_char(input_bytes: bytes, decoding_char: bytes):
    return set1_2_hex_xor.bytes_xor(input_bytes, decoding_char*len(input_bytes))

if __name__ == '__main__':
    bytes_str = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    all_bytes = [bytes.fromhex(k1 + k2) for k1 in HEX_MAP.keys() for k2 in HEX_MAP.keys()]
    alphabet_bytes = b'abcdefghijklmnopqrstuvwxyz0123456789 '

    for byte in all_bytes:
        score = 0
        for decoded_byte in xor_against_single_char(bytes_str, byte):
            if bytes([decoded_byte]) in alphabet_bytes:
                score = score + 1
        if score > .8*len(bytes_str):
            print(f'decoding byte: {byte}, decoded string:\n{xor_against_single_char(bytes_str, byte)}')
