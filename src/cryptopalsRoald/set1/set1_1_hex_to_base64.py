from cryptopalsRoald.roald_codecs import HEX_TO_BASE64

def grouped(iterable, n):
    "s -> (s0,s1,s2,...sn-1), (sn,sn+1,sn+2,...s2n-1), (s2n,s2n+1,s2n+2,...s3n-1), ..."
    return zip(*[iter(iterable)]*n)

def hex2base64(hex_str: str) -> str:
    assert len(hex_str)%2 == 0

    if len(hex_str)%6 == 0:
        my_list = [HEX_TO_BASE64[''.join(item)] for item in grouped(hex_str, 3)]
    elif len(hex_str)%6 == 4:
        my_list = [HEX_TO_BASE64[''.join(item)] for item in grouped(hex_str[:-4], 3)]
        my_list.extend([HEX_TO_BASE64[hex_str[-4:-1]], HEX_TO_BASE64[hex_str[-1:] + '00'][0], '='])
    else:
        my_list = [HEX_TO_BASE64[''.join(item)] for item in grouped(hex_str[:-2], 3)]
        my_list.extend([HEX_TO_BASE64[hex_str[-2:] + '0'], '=='])
    return ''.join(my_list)

if __name__ == '__main__':
    hex_str = '49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d'
    base64_str = 'SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t'
    print(hex2base64(hex_str))
    print(hex2base64(hex_str[:-2]))
    print(hex2base64(hex_str[:-4]))
    assert base64_str == hex2base64(hex_str)
