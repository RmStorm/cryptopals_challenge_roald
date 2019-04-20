import os
import base64

import pytest

from cryptopals_challenge_roald.set3.set3_17_cbc_padding_oracle import cbc_padding_oracle_attack, \
    get_cbc_encryptor_and_decryptor_of_set_17_data
DIR_PATH = os.path.dirname(os.path.realpath(__file__))


def test_set_3_17():
    with open(os.path.join(DIR_PATH, '..', 'data', 'set3_17_data'), 'br') as file_handle:
        data_lines = file_handle.read().splitlines()
    cracked_line = cbc_padding_oracle_attack(*get_cbc_encryptor_and_decryptor_of_set_17_data(4))
    assert base64.b64decode(data_lines[4]) == cracked_line



if __name__ == '__main__':
    pytest.main()
