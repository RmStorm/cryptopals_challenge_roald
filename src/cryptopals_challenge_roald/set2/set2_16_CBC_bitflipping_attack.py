import os

from cryptopals_challenge_roald.roald_codecs import BIT_FLIP_MAP
from cryptopals_challenge_roald.crypto_lib import AesCbcCipher, verify_and_remove_pkcs_7_padding


def get_cbc_encryptor_and_decryptor():
    unknown_key = os.urandom(16)
    aes_cbc_cipher = AesCbcCipher(unknown_key, os.urandom(16))
    prepend_bytes = b'comment1=cooking%20MCs;userdata='
    append_bytes = b';comment2=%20like%20a%20pound%20of%20bacon'

    def encryptor(attacker_controlled: bytes) -> bytes:
        cleaned_bytes = attacker_controlled.replace(b';', b' ').replace(b'=', b' ')
        return aes_cbc_cipher.encrypt(prepend_bytes + cleaned_bytes + append_bytes)

    def decryptor(cipher_text: bytes) -> bool:
        plain_text = verify_and_remove_pkcs_7_padding(aes_cbc_cipher.decrypt(cipher_text))
        # Notice that this will throw an error sometimes, Since there are bitflips in one block of the cipher text,
        # one block of the plain text will be scrambled,
        # A random b';' could pop up in the plain text. this breaks the cookie creation.
        cookie_dict = {k_v_str.split(b'=')[0]: k_v_str.split(b'=')[1] for k_v_str in plain_text.split(b';')}
        return True if b'admin' in cookie_dict and cookie_dict[b'admin'] == b'true' else False
    return encryptor, decryptor


def get_prepend_padding_length_and_block_index(block_size, encryptor):
    """To craft the attack it is easiest if the prepended bytes are an integer multiple of the block_size, this
    function figures out how many bytes need to be padded to mae that happen. Than the next block can be used in the
    attack, the index of this block is also returned"""

    def block_getter(byte_str: bytes, block: int) -> bytes:
        return byte_str[block * block_size:(1 + block) * block_size]

    def get_num_of_identical_blocks(cipher1, cipher2):
        for cipher_block_index in range(int(len(cipher2) / block_size)):
            if not block_getter(cipher1, cipher_block_index) == block_getter(cipher2, cipher_block_index):
                return cipher_block_index

    prev_cipher = encryptor(b'\x00')
    prev_highest_identical_block = get_num_of_identical_blocks(encryptor(b''), prev_cipher)
    for prepend_padding_length in range(2, block_size * 3):
        cur_cipher = encryptor(bytes([0])*prepend_padding_length)
        cur_highest_identical_block = get_num_of_identical_blocks(prev_cipher, cur_cipher)
        if cur_highest_identical_block > prev_highest_identical_block:
            return prepend_padding_length, cur_highest_identical_block
        prev_cipher = cur_cipher


def get_admin_cipher(block_size, encryptor, decryptor):
    """The basic shape of the attack is to insert userdata with ;admin=true appended at the end, however the critical
    symbols ; and = are escaped so we use bitflipped versions: b';'[0] + 128) % 256

    The trick is to prepend our actual attack bytes with a block of zeros, than we can bitflip the right bytes in the
    cipher text such that our decrypted plain text has the string ;admin=true

    To do this we need to do a little bit of investigating: There are some bytes prepended to our userdata, we need to
    fill out those bytes such that they take up an integer number of bytes wrt to the block size, Than we need to know
    the which block of the cipher text is the block after those blocks."""
    prepend_padding_length, highest_identical_block = get_prepend_padding_length_and_block_index(block_size, encryptor)
    cipher_text = bytearray(encryptor(bytes([0]) * (prepend_padding_length + block_size + 5) +
                                      bytes([(b';'[0] + 128) % 256]) + b'admin' +
                                      bytes([(b'='[0] + 128) % 256]) + b'true'))

    for i in [block_size - 10, block_size - 4]:
        index_of_interest = block_size * highest_identical_block + i
        cipher_text[index_of_interest] = BIT_FLIP_MAP[cipher_text[index_of_interest]]

    try:
        if decryptor(cipher_text):
            return cipher_text
    except IndexError:
        index_of_interest = block_size * highest_identical_block
        cipher_text[index_of_interest] = BIT_FLIP_MAP[cipher_text[index_of_interest]]
        if decryptor(cipher_text):
            return cipher_text
    raise RuntimeError('Did not succeed in finding a cipher text that makes you admin')


def main():
    block_size = 16
    encryptor, decryptor = get_cbc_encryptor_and_decryptor()

    cipher_text = get_admin_cipher(block_size, encryptor, decryptor)

    print(cipher_text)
    print(decryptor(cipher_text))


if __name__ == '__main__':
    main()
