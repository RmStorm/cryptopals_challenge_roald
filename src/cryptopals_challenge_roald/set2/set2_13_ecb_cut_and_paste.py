import re
from typing import Dict

import json

EMAIL_REGEX = re.compile("(^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$)")


def cookie_parser(input_str: str) -> Dict:
    """Takes input like: foo=bar&baz=qux&zap=zazzle and parses it into a dict"""
    return {k_v_str.split('=')[0]: k_v_str.split('=')[1] for k_v_str in input_str.split('&')}


def cookie_baker(input_dict: Dict) -> str:
    return '&'.join([f'{k}={v}' for k, v in input_dict.items()])


def profile_for(email: str) -> Dict:
    """Accepts an email adress and returns a user object with an id and role"""
    assert EMAIL_REGEX.match(email)
    return {'email': email, 'uid': 10, 'role': 'user'}


def main():
    print(json.dumps(cookie_parser('foo=bar&baz=qux&zap=zazzle'), indent=2))
    print(cookie_baker(cookie_parser('foo=bar&baz=qux&zap=zazzle')))


if __name__ == '__main__':
    main()
