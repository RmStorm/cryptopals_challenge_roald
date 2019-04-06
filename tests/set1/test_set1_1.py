import pytest

from cryptopalsRoald.set1 import set1_1_hex_to_base64
from cryptopalsRoald.set1 import set1_2_hex_xor


def test_set_1_1():
    hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    base64_str = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    assert base64_str == set1_1_hex_to_base64.hex2base64_bytes(hex_str)

def test_set_1_2():
    str1 = '1c0111001f010100061a024b53535009181c'
    str2 = '686974207468652062756c6c277320657965'
    xor_result = '746865206b696420646f6e277420706c6179'
    assert xor_result == set1_2_hex_xor.bytes_xor(bytes.fromhex(str1), bytes.fromhex(str2)).hex()

if __name__ == '__main__':
    pytest.main()
