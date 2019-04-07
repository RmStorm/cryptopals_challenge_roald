import os
import base64

import pytest

from cryptopals_challenge_roald.crypto_lib import apply_pkcs_7_padding, AesCbcCipher

DIR_PATH = os.path.dirname(os.path.realpath(__file__))


@pytest.mark.parametrize("block_length", [4, 8, 16, 20, 36])
def test_set_2_1(block_length):
    bytes_str = b'A random string with some characters'

    padded = apply_pkcs_7_padding(bytes_str, block_length)
    if len(bytes_str) % block_length == 0:
        assert len(padded) == len(bytes_str)
    else:
        assert padded[:-padded[-1]] == bytes_str
    assert len(padded) % block_length == 0


def test_set_2_2():
    with open(os.path.join(DIR_PATH, '..', 'data', 'set2_10_data'), 'br') as file_handle:
        encrypted_bytes = base64.b64decode(file_handle.read())
    key = b'YELLOW SUBMARINE'
    aes_cbc_cipher = AesCbcCipher(key, bytes([0])*len(key))
    print(aes_cbc_cipher.decrypt(encrypted_bytes))


if __name__ == '__main__':
    pytest.main()
