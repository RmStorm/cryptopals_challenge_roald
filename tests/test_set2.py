import os
import base64

import pytest
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptopals_challenge_roald.crypto_lib import AesEcbCipher, AesCbcCipher, crack_ecb_encryptor, \
    apply_pkcs_7_padding, verify_and_remove_pkcs_7_padding, PaddingError
from cryptopals_challenge_roald.set2.set2_11_ecb_cbc_detection_oracle import encryption_oracle
from cryptopals_challenge_roald.set2.set2_12_byte_at_a_time_ecb_decryption import get_encryptor_with_attacker_prepend
from cryptopals_challenge_roald.set2.set2_13_ecb_cut_and_paste import profile_for
from cryptopals_challenge_roald.set2.set2_14_ecb_baat_random_prefix import get_encryptor_with_attack_bytes_in_middle,\
    crack_ecb_encryptor_with_random_prepend, get_attack_length_for_cipher_increase
from cryptopals_challenge_roald.set2.set2_16_cbc_bitflipping_attack import get_cbc_encryptor_and_decryptor,\
    get_admin_cipher
DIR_PATH = os.path.dirname(os.path.realpath(__file__))


@pytest.mark.parametrize("block_size", [4, 8, 16, 20, 36])
def test_set_2_9(block_size):
    bytes_str = b'A random string with some characters'

    padded = apply_pkcs_7_padding(bytes_str, block_size)
    if len(bytes_str) % block_size == 0:
        assert len(padded) == len(bytes_str) + block_size
    else:
        assert padded[:-padded[-1]] == bytes_str
        assert padded[-padded[-1]:] == bytes([padded[-1]])*padded[-1]
    assert len(padded) % block_size == 0


def test_set_2_10():
    with open(os.path.join(DIR_PATH, '..', 'data', 'set2_10_data'), 'br') as file_handle:
        encrypted_bytes = base64.b64decode(file_handle.read())
    key = b'YELLOW SUBMARINE'
    aes_cbc_cipher = AesCbcCipher(key, bytes([0])*len(key))

    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.CBC(bytes([0])*len(key)), backend=backend)
    library_cbc_output = verify_and_remove_pkcs_7_padding(cipher.decryptor().update(encrypted_bytes))
    assert library_cbc_output == aes_cbc_cipher.decrypt(encrypted_bytes)


def test_set_2_11():
    def ecb_encryptor(encryptable_bytes, key):
        return AesEcbCipher(key).encrypt(encryptable_bytes)

    def cbc_encryptor(encryptable_bytes, key):
        return AesCbcCipher(key, os.urandom(len(key))).encrypt(encryptable_bytes)

    assert encryption_oracle(ecb_encryptor) == 'ECB'
    assert encryption_oracle(cbc_encryptor) == 'Not ECB'


def test_set_2_12():
    encryptor = get_encryptor_with_attacker_prepend()
    known_solution = b'Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\n' \
                     b'The girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n'

    assert crack_ecb_encryptor(encryptor, 16, 138, 0) == known_solution


@pytest.mark.parametrize("user_email", ['it@it.com', 'it@it.com', 'it@it.com'])
def test_set_2_13(user_email):
    import json

    print(json.dumps(profile_for(user_email), indent=2))


def test_set_2_14():
    encryptor = get_encryptor_with_attack_bytes_in_middle(2, 1)
    known_solution = b'Rollin\' in my 5.0\nWith my rag-top down so my hair can blow\n' \
                     b'The girlies on standby waving just to say hi\nDid you stop? No, I just drove by\n'

    attack_length = get_attack_length_for_cipher_increase(encryptor, retries_for_max=10)
    assert crack_ecb_encryptor_with_random_prepend(encryptor, 16, attack_length, retries_for_max=10) == known_solution


def test_set_2_15():
    assert verify_and_remove_pkcs_7_padding(b'ICE ICE BABY\x04\x04\x04\x04') == b'ICE ICE BABY'
    with pytest.raises(PaddingError):
        verify_and_remove_pkcs_7_padding(b'ICE ICE BABY\x05\x05\x05\x05')


def test_set_2_16():
    block_size = 16
    encryptor, decryptor = get_cbc_encryptor_and_decryptor()
    cipher_text = get_admin_cipher(block_size, encryptor, decryptor)

    assert decryptor(cipher_text)


if __name__ == '__main__':
    pytest.main(['test_set2.py'])
