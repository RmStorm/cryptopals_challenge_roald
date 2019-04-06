from cryptopalsRoald.roald_codecs import HEX_PAIR_XOR, BIT_TO_HEX

def hex_xor(hex_str1: str, hex_str2: str) -> str:
    return(''.join([BIT_TO_HEX[HEX_PAIR_XOR[''.join(item)]] for item in zip(hex_str1, hex_str2)]))

if __name__ == '__main__':
    str1 = '1c0111001f010100061a024b53535009181c'
    str2 = '686974207468652062756c6c277320657965'
    print(hex_xor(str1, str2))
