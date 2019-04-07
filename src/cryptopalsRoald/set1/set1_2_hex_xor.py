from cryptopalsRoald.crypto_lib import bytes_xor

if __name__ == '__main__':
    str1 = '1c0111001f010100061a024b53535009181c'
    str2 = '686974207468652062756c6c277320657965'
    print(bytes_xor(bytes.fromhex(str1), bytes.fromhex(str2)))
