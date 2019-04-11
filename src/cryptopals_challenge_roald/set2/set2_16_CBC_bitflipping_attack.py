import os
from typing import Dict

from cryptopals_challenge_roald.roald_codecs import BIT_FLIP_MAP
from cryptopals_challenge_roald.crypto_lib import AesCbcCipher, verify_and_remove_pkcs_7_padding


def get_cbc_encryptor_and_decryptor():
    unknown_key = os.urandom(16)
    aes_cbc_cipher = AesCbcCipher(unknown_key, os.urandom(16))
    prepend_bytes = b'comment1=cooking%20MCs;userdata='
    append_bytes = b';comment2=%20like%20a%20pound%20of%20bacon'

    def encryptor(attacker_controlled: bytes) -> bytes:
        cleaned_bytes = attacker_controlled.replace(b';', b' ').replace(b'=', b' ')
        return aes_cbc_cipher.encrypt(prepend_bytes + cleaned_bytes + append_bytes)

    def decryptor(cipher_text: bytes) -> Dict:
        input_text = verify_and_remove_pkcs_7_padding(aes_cbc_cipher.decrypt(cipher_text))
        return {k_v_str.split('=')[0]: k_v_str.split('=')[1] for k_v_str in input_text.decode('utf-8').split(';')}
    return encryptor, decryptor


def main():
    encryptor, decryptor = get_cbc_encryptor_and_decryptor()
    semi_colon_bits = list(f"{b';'[0]:08b}")
    print(semi_colon_bits)
    semi_colon_bits[0] = str(abs(int(semi_colon_bits[0])-1))
    print(semi_colon_bits)
    print(BIT_FLIP_MAP[b';'])
    print(decryptor(encryptor(b'ja toch dit is gebruikers data;=;')))


if __name__ == '__main__':
    main()
