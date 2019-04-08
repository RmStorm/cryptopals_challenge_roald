import os
# import re
from typing import Dict

from cryptopals_challenge_roald.crypto_lib import AesEcbCipher

# EMAIL_REGEX = re.compile("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")
AES_ECB_CIPHER = AesEcbCipher(os.urandom(16))


def cookie_parser(input_str: str) -> Dict:
    """Takes input like: foo=bar&baz=qux&zap=zazzle and parses it into a dict"""
    return {k_v_str.split('=')[0]: k_v_str.split('=')[1] for k_v_str in input_str.split('&')}


def cookie_baker(input_dict: Dict) -> str:
    return '&'.join([f'{k}={v}' for k, v in input_dict.items()])


def profile_for(email: str) -> Dict:
    """Accepts an email adress and returns a user object with an id and role"""
    email = email.replace('&', '').replace('=', '')
    return {'email': email, 'uid': 10, 'role': 'user'}


def get_encrypted_and_encoded_profile(email: str):
    return AES_ECB_CIPHER.encrypt(bytes(cookie_baker(profile_for(email)), 'utf-8'))

def main():
    print(get_encrypted_and_encoded_profile(chr(8) + 'aaaa@a.a'))


if __name__ == '__main__':
    main()
