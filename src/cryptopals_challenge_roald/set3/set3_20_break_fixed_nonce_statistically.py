from cryptopals_challenge_roald.set3.set3_19_break_fixed_nonce_ctr import encrypt_with_same_nonce, \
    get_initial_likely_bytes, print_cipher_text_with_colored_n


def main():
    cipher_texts = encrypt_with_same_nonce('set3_20_data')
    possible_xor_byte_dicts, possible_xor_bytes = get_initial_likely_bytes(cipher_texts, truncated=True)
    print_cipher_text_with_colored_n(cipher_texts, possible_xor_bytes)


if __name__ == '__main__':
    main()
