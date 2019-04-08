import os
import base64

import pytest

from cryptopals_challenge_roald.crypto_lib import apply_pkcs_7_padding, AesEcbCipher, AesCbcCipher
from cryptopals_challenge_roald.set2.set2_11_ecb_cbc_detection_oracle import encryption_oracle
from cryptopals_challenge_roald.set2 import set2_12_byte_at_a_time_ecb_decryption
from cryptopals_challenge_roald.set2.set2_13_ecb_cut_and_paste import profile_for

DIR_PATH = os.path.dirname(os.path.realpath(__file__))


@pytest.mark.parametrize("block_length", [4, 8, 16, 20, 36])
def test_set_2_9(block_length):
    bytes_str = b'A random string with some characters'

    padded = apply_pkcs_7_padding(bytes_str, block_length)
    if len(bytes_str) % block_length == 0:
        assert len(padded) == len(bytes_str)
    else:
        assert padded[:-padded[-1]] == bytes_str
        assert padded[-padded[-1]:] == bytes([padded[-1]])*padded[-1]
    assert len(padded) % block_length == 0


def test_set_2_10():
    with open(os.path.join(DIR_PATH, '..', 'data', 'set2_10_data'), 'br') as file_handle:
        encrypted_bytes = base64.b64decode(file_handle.read())
    key = b'YELLOW SUBMARINE'
    aes_cbc_cipher = AesCbcCipher(key, bytes([0])*len(key))

    from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
    from cryptography.hazmat.backends import default_backend

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes([0])*len(key)), backend=backend)
    assert cipher.decryptor().update(encrypted_bytes) == aes_cbc_cipher.decrypt(encrypted_bytes)


def test_set_2_11():
    def ecb_encryptor(encryptable_bytes, key):
        return AesEcbCipher(key).encrypt(encryptable_bytes)
    def cbc_encryptor(encryptable_bytes, key):
        return AesCbcCipher(key, os.urandom(len(key))).encrypt(encryptable_bytes)

    assert encryption_oracle(ecb_encryptor) == 'ECB'
    assert encryption_oracle(cbc_encryptor) == 'Not ECB'


def test_set_2_12():
    encryptor = set2_12_byte_at_a_time_ecb_decryption.get_encryptor_with_input_prepend()
    known_solution = b'Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\n' \
                     b'The girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n'

    assert set2_12_byte_at_a_time_ecb_decryption.crack_ecb_encryptor(encryptor, 16, 138) == known_solution


@pytest.mark.parametrize("user_email", ['it@it.com', 'it@it.com', 'it@it.com'])
def test_set_2_13(user_email):
    import json

    print(json.dumps(profile_for(user_email), indent=2))
    # assert False


if __name__ == '__main__':
    pytest.main()
