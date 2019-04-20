import base64
import struct

from cryptopals_challenge_roald.crypto_lib import AesCtrCipher


def main():
    encrypted_bytes = base64.decodebytes(b'L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==')
    aes_ctr_cipher = AesCtrCipher(b'YELLOW SUBMARINE', struct.pack('<Q', 0))
    assert b"Yo, VIP Let\'s kick it Ice, Ice, baby Ice, Ice, baby " == aes_ctr_cipher.encrypt(encrypted_bytes)


if __name__ == '__main__':
    main()
