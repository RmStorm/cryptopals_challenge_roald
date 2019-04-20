import os
import base64
import struct

import pytest

from cryptopals_challenge_roald.crypto_lib import AesCtrCipher
from cryptopals_challenge_roald.set3.set3_17_cbc_padding_oracle import cbc_padding_oracle_attack, \
    get_cbc_encryptor_and_decryptor_of_set_17_data
DIR_PATH = os.path.dirname(os.path.realpath(__file__))


def test_set_3_17():
    with open(os.path.join(DIR_PATH, '..', 'data', 'set3_17_data'), 'br') as file_handle:
        data_lines = file_handle.read().splitlines()
    cracked_line = cbc_padding_oracle_attack(*get_cbc_encryptor_and_decryptor_of_set_17_data(4))
    assert base64.b64decode(data_lines[4]) == cracked_line


def test_set_3_18():
    """I test my implementation against a string instead of the cryptography library, this is because my implementation
    is supposed to concat the nonce and the counter. The crypto library adds the counter to the nonce"""
    encrypted_bytes = base64.decodebytes(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    aes_ctr_cipher = AesCtrCipher(b'YELLOW SUBMARINE', struct.pack('<Q', 0))
    assert b"Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby " == aes_ctr_cipher.encrypt(encrypted_bytes)

    some_other_string = b'some_other_string'
    assert aes_ctr_cipher.encrypt(aes_ctr_cipher.encrypt(some_other_string)) == some_other_string

if __name__ == '__main__':
    pytest.main()
