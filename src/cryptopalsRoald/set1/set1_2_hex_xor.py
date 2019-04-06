def hex_xor(hex_str1: str, hex_str2: str) -> bytearray:
    return bytearray(a ^ b for a, b in zip(bytearray.fromhex(hex_str1), bytearray.fromhex(hex_str2)))

if __name__ == '__main__':
    str1 = '1c0111001f010100061a024b53535009181c'
    str2 = '686974207468652062756c6c277320657965'
    print(hex_xor(str1, str2))
