from cryptopals_challenge_roald.set3.set3_19_break_fixed_nonce_ctr import encrypt_with_same_nonce

def main():
    cipher_texts = encrypt_with_same_nonce('set3_20_data')
    print(cipher_texts)

if __name__ == '__main__':
    main()
