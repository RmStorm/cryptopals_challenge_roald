import os
from itertools import cycle

import pytest

from cryptopalsRoald.set1 import set1_1_hex_to_base64
from cryptopalsRoald.set1.set1_2_hex_xor import bytes_xor
from cryptopalsRoald.set1.set1_3_decode_hex import decode_byte_string_with_bytes
from cryptopalsRoald.set1.set1_6_break_repeating_key_xor import compute_hamming_distance


def test_set_1_1():
    hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    base64_str = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert base64_str == set1_1_hex_to_base64.hex2base64_bytes(hex_str)

def test_set_1_2():
    str1 = '1c0111001f010100061a024b53535009181c'
    str2 = '686974207468652062756c6c277320657965'
    xor_result = '746865206b696420646f6e277420706c6179'
    assert xor_result == bytes_xor(bytes.fromhex(str1), bytes.fromhex(str2)).hex()


def test_set_1_3():
    bytes_str = bytes.fromhex('1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736')
    for k, v in decode_byte_string_with_bytes(bytes_str, .8).items():
        assert k == b'X'
        assert v == b"Cooking MC's like a pound of bacon"


def test_set_1_4():
    with open(os.path.join(os.getcwd(), '..', '..', 'data', 'set1_4_data'), 'r') as file_handle:
        for line_number, line in enumerate(file_handle):
            result = decode_byte_string_with_bytes(bytes.fromhex(line), .9)
            for k, v in result.items():
                assert k == b'5'
                assert v == b'Now that the party is jumping\n'
                break


def test_set_1_5():
    my_string = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    encoded_string = '0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272' \
                     'a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f'
    assert bytes_xor(my_string, cycle(b'ICE')).hex() == encoded_string


def test_set_1_6():
    str1 = b'this is a test'
    str2 = b'wokka wokka!!!'
    compute_hamming_distance(str1, str2)

if __name__ == '__main__':
    pytest.main()
