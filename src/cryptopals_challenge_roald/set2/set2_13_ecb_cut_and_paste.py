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
    # The starting assumption is the knowledge that a decrypted cookie looks like: email=emailadress&uid=10&role=user
    # The first step is to fill up the first codeblock with nonsense and find a code block for the padded word 'admin'
    admin_suffix = get_encrypted_and_encoded_profile(chr(0)*(16-len('email=')) + 'admin' + chr(11)*11)[16:32]
    # The second step is to make email=emailadress&uid=10&role= take up exactly 32 bytes
    print(len('email='), len('roald@awe.som'), len('&uid=10&role='))
    email_part = get_encrypted_and_encoded_profile('roald@awe.som')[:32]
    result = AES_ECB_CIPHER.decrypt(email_part+admin_suffix)
    print(result[:-result[-1]])


if __name__ == '__main__':
    main()
