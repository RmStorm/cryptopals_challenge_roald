import os
import base64

import pytest

from cryptopals_challenge_roald.crypto_lib import AesCtrCipher, bytes_xor
from cryptopals_challenge_roald.set3.set3_17_cbc_padding_oracle import cbc_padding_oracle_attack, \
    get_cbc_encryptor_and_decryptor_of_set_17_data
from cryptopals_challenge_roald.set3.set3_19_break_fixed_nonce_ctr import encrypt_with_same_nonce, \
    get_initial_likely_bytes
from cryptopals_challenge_roald.set3.set3_21_mersenne_prng import MersenneTwister
from cryptopals_challenge_roald.set3.set3_23_copy_mersenne_twister_state import un_temper

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
    aes_ctr_cipher = AesCtrCipher(b'YELLOW SUBMARINE', 0)
    assert b"Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby " == aes_ctr_cipher.encrypt(encrypted_bytes)

    some_other_string = b'some_other_string'
    assert aes_ctr_cipher.encrypt(aes_ctr_cipher.encrypt(some_other_string)) == some_other_string


@pytest.mark.slow
def test_set_3_19_20():
    test_set = 'set3_20_data'
    with open(os.path.join(DIR_PATH, '..', 'data', test_set), 'br') as file_handle:
        data_lines = [base64.b64decode(data_line) for data_line in file_handle.read().splitlines()]

    cipher_texts = encrypt_with_same_nonce(test_set)
    possible_xor_byte_dicts, possible_xor_bytes = get_initial_likely_bytes(cipher_texts, truncated=True)

    for cipher_text, answer in zip(cipher_texts, data_lines):
        assert answer[:len(possible_xor_bytes)] == bytes_xor(cipher_text, possible_xor_bytes)


def test_set_3_21():
    """Test Mersenne Twister with data from https://create.stephan-brumme.com/mersenne-twister/"""
    correct = {5489: [0xD091BB5C, 0x22AE9EF6, 0xE7E1FAEE, 0xD5C31F79, 0x2082352C, 0xF807B7DF,
                      0xE9D30005, 0x3895AFE1, 0xA1E24BBA, 0x4EE4092B]}

    mersenne_twister = MersenneTwister()
    for seed, answers in correct.items():
        mersenne_twister.seed(seed)
        for num in answers:
            assert num == mersenne_twister.generate_number()


def test_set_3_22():
    mersenne_twister = MersenneTwister()
    mersenne_twister.seed(87634)
    w, n, m, r, a, b, c, s, t, u, d, l, f = mersenne_twister.output_all()

    random_numbers = [mersenne_twister.generate_number() for _ in range(10)]
    for num in random_numbers:
        assert num == un_temper(mersenne_twister.temper_output(num), w, b, c, d, u, s, t, l)


if __name__ == '__main__':
    pytest.main(['test_set3.py'])
