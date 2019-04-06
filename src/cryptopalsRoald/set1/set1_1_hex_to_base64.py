import base64

def hex2base64_bytes(hex_str: str) -> bytearray:
    return base64.b64encode(bytearray.fromhex(hex_str))

if __name__ == '__main__':
    hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    base64_str = b'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    print(hex2base64_bytes(hex_str))
    print(hex2base64_bytes(hex_str[:-2]))
    print(hex2base64_bytes(hex_str[:-4]))
    assert base64_str == hex2base64_bytes(hex_str)
