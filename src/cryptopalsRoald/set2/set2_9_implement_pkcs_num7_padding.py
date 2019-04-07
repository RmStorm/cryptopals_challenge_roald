from cryptopalsRoald.crypto_lib import apply_pkcs_7_padding


def main():
    bytes_str = b'YELLOW SUBMARINE'
    assert b'YELLOW SUBMARINE\x04\x04\x04\x04' == apply_pkcs_7_padding(bytes_str, 20)


if __name__ == '__main__':
    main()
