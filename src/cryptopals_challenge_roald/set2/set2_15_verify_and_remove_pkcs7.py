from cryptopals_challenge_roald.crypto_lib import verify_and_remove_pkcs_7_padding

def main():
    correct_padding = b'ICE ICE BABY\x04\x04\x04\x04'
    incorrect_padding = [b'ICE ICE BABY\x05\x05\x05\x05', b'ICE ICE BABY\x01\x02\x03\x04']
    print(len(correct_padding))
    [print(len(p)) for p in incorrect_padding]
    print(verify_and_remove_pkcs_7_padding(b'Nopadding'))
    print(verify_and_remove_pkcs_7_padding(correct_padding))
    print(verify_and_remove_pkcs_7_padding(incorrect_padding[0]))
    print(verify_and_remove_pkcs_7_padding(incorrect_padding[1]))


if __name__ == '__main__':
    main()
