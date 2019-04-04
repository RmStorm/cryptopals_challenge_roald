import pytest

from cryptopalsRoald.set1 import set1_1_hex_to_base64


def test_set_1():
    assert 'str' == set1_1_hex_to_base64.hex2base64('str')

if __name__ == '__main__':
    pytest.main()
