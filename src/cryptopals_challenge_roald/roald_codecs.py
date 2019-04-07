BASE64MAP = {'A': 0, 'B': 1, 'C': 2, 'D': 3, 'E': 4, 'F': 5, 'G': 6, 'H': 7, 'I': 8, 'J': 9, 'K': 10, 'L': 11,
             'M': 12, 'N': 13, 'O': 14, 'P': 15, 'Q': 16, 'R': 17, 'S': 18, 'T': 19, 'U': 20, 'V': 21, 'W': 22,
             'X': 23, 'Y': 24, 'Z': 25, 'a': 26, 'b': 27, 'c': 28, 'd': 29, 'e': 30, 'f': 31, 'g': 32, 'h': 33,
             'i': 34, 'j': 35, 'k': 36, 'l': 37, 'm': 38, 'n': 39, 'o': 40, 'p': 41, 'q': 42, 'r': 43, 's': 44,
             't': 45, 'u': 46, 'v': 47, 'w': 48, 'x': 49, 'y': 50, 'z': 51, '0': 52, '1': 53, '2': 54, '3': 55,
             '4': 56, '5': 57, '6': 58, '7': 59, '8': 60, '9': 61, '+': 62, '/': 63}

HEX_MAP = {'0': 0, '1': 1, '2': 2, '3': 3, '4': 4, '5': 5, '6': 6, '7': 7, '8': 8, '9': 9, 'a': 10, 'b': 11, 'c': 12,
           'd': 13, 'e': 14, 'f': 15}

BASE64_TO_BIT = {k: f'{v:06b}' for k, v in BASE64MAP.items()}
BIT_TO_BASE64 = {f'{v:06b}': k for k, v in BASE64MAP.items()}

HEX_TO_BIT = {k: f'{v:04b}' for k, v in HEX_MAP.items()}
BIT_TO_HEX = {f'{v:04b}': k for k, v in HEX_MAP.items()}

HEX_TO_BASE64 = {ak+bk+ck: BIT_TO_BASE64[av+bv[:2]]+BIT_TO_BASE64[bv[-2:]+cv]
                 for ak, av in HEX_TO_BIT.items() for bk, bv in HEX_TO_BIT.items() for ck, cv in HEX_TO_BIT.items()}

HEX_PAIR_XOR = {ak + bk: ''.join(['1' if int(av_num) + int(bv_num) == 1 else '0' for av_num, bv_num in zip(av, bv)])
                for ak, av in HEX_TO_BIT.items() for bk, bv in HEX_TO_BIT.items()}
