import pytest

from cryptopalsRoald.crypto_lib import apply_pkcs_7_padding

@pytest.mark.parametrize("block_length", [4, 8, 16, 20, 36])
def test_set_2_1(block_length):
    bytes_str = b'A random string with some characters'

    padded = apply_pkcs_7_padding(bytes_str, block_length)
    assert len(padded)%block_length == 0
    assert padded[:-padded[-1]] == bytes_str

if __name__ == '__main__':
    pytest.main()
