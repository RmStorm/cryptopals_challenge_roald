def apply_pkcs_7_padding(input_bytes: bytes, block_length: int) -> bytes:
    padding_length = block_length - len(input_bytes)%block_length
    return input_bytes + bytes([padding_length])*padding_length


def main():
    bytes_str = b'YELLOW SUBMARINE'
    assert b'YELLOW SUBMARINE\x04\x04\x04\x04' == apply_pkcs_7_padding(bytes_str, 20)


if __name__ == '__main__':
    main()
