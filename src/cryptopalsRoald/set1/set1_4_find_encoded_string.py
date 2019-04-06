import os
from cryptopalsRoald.set1 import set1_3_decode_hex

if __name__ == '__main__':
    print(os.getcwd())
    # print(os.getp)
    with open(os.path.join(os.getcwd(),'set1_4_data'), 'r') as file_handle:
        for line in file_handle:
            result = set1_3_decode_hex.decode_byte_string_with_bytes(bytes.fromhex(line), .9)
            if result:
                print(line)
                print(result)