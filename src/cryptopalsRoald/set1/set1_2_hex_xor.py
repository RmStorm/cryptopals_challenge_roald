def bytes_xor(byte_str1: bytes, byte_str2: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(byte_str1, byte_str2))

if __name__ == '__main__':
    str1 = '1c0111001f010100061a024b53535009181c'
    str2 = '686974207468652062756c6c277320657965'
    print(bytes_xor(bytes.fromhex(str1), bytes.fromhex(str2)))
