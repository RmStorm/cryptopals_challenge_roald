from cryptopalsRoald.roald_codecs import HEX_TO_BIT
from cryptopalsRoald.set1.set1_2_hex_xor import bytes_xor

def compute_hamming_distance(bytes_str1, bytes_str2) -> int:
    return sum(int(a) for item in bytes_xor(bytes_str1, bytes_str2).hex() for a in HEX_TO_BIT[item])


if __name__ == '__main__':
    str1 = b'this is a test'
    str2 = b'wokka wokka!!!'
    print(compute_hamming_distance(str1, str2))
