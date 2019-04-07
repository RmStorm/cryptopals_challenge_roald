from itertools import cycle
from cryptopals_challenge_roald.set1.set1_2_hex_xor import bytes_xor

if __name__ == '__main__':
    my_string = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    print(bytes_xor(my_string, cycle(b'ICE')).hex())
    print(bytes_xor(bytes_xor(my_string, cycle(b'ICE')), cycle(b'ICE')))
