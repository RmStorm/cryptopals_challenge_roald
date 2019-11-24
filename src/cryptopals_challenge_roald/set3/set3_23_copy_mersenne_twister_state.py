import datetime as dt

from cryptopals_challenge_roald.set3.set3_21_mersenne_prng import MersenneTwister


def print_bits(num, bits=32):
    print(f'yi = {num:0{bits}b}={num}')


def unscramble(sol: int, y: int, shift: int, bit_mask: int, r: int = 0, dir: str = 'right'):
    """
    This function recursively unscrambles the tempering done by the mersenne twister. It works like this:
    scrambling is off the form:
    yn+1 = yn ^ ((yn << shift) & bit_mask)
    and since xorring is it's own inverse:
    yn ^ yn+1 = ((yn << shift) & bit_mask)
    yn = ((yn << shift) & bit_mask) ^ yn+1

    CASE: shift > len(yn)/2
    When the shift is more than half the length of the integer yn, unscrambling is straightforward. Because of the xor
    operation the least significant bits up to 'shift' in yn+1 are equivalent to the least significant bits in yn:
    yn+1[-shift:] == yn[-shift:] This also means that:
    ((yn+1 << shift) & bit_mask) == ((yn << shift) & bit_mask)
    Since xorring is it's own inverse you can now retrieve the entire number yn by xorring with yn+1
    yn = ((yn+1 << shift) & bit_mask) ^ yn+1
    This only works when shift > len(yn)/2, otherwise there will be additional bits that have to get unscrambled.

    CASE: shift < len(yn)/2
    We can use the previous method to calculate the least significant 2*shift bits like this:
    y_intermediate = (yn+1 << shift) & bit_mask) ^ yn+1
    y_intermediate[-2*shift:] = yn[-2*shift:]
    y_intermediate[:-2*shift] = wrong bits
    by repeating the procedure with y_intermediate another 'shift' bits can be gotten:
    y_intermediate2 = (y_intermediate << shift) & bit_mask) ^ y_intermediate
    y_intermediate2[-3*shift:] = yn[-3*shift:]
    and so on until yn is recovered.

    :param sol: partially solved instance of yn (as first guess just yn+1)
    :param y: yn+1
    :param shift: size of shift
    :param bit_mask: bitmask used in and operation
    :param r: required recursion depth to get answer
    :param dir: direstion of shift
    :return: yn
    """
    new_sol = (((sol >> shift) if dir=='right' else (sol << shift)) & bit_mask) ^ y
    return new_sol if r == 0 else unscramble(new_sol, y, shift, bit_mask, r-1, dir)


def un_temper(y4, w, b, c, d, u, s, t, l):
    """
    This functions undoes the tempering from a mersenne twister
    y1 = y ^ ((y >> u) & d)
    y2 = y1 ^ ((y1 << s) & b)
    y3 = y2 ^ ((y2 << t) & c)
    y4 = y3 ^ (y3 >> l)
    return y4
    """
    y3 = unscramble(y4, y4, l, int('1'*w, 2))
    y2 = unscramble(y3, y3, t, c, 0, 'left')
    y1 = unscramble(y2, y2, s, b, round(w/s-2), 'left')
    return unscramble(y1, y1, u, d, round(w/u-2))


def main():
    mersenne_twister_spliced = MersenneTwister()
    mersenne_twister_spliced.seed()

    mersenne_twister = MersenneTwister()
    mersenne_twister.seed(int(dt.datetime.now().timestamp()))
    w, n, m, r, a, b, c, s, t, u, d, l, f = mersenne_twister.output_all()

    for _ in range(125):
        # They are not the same
        assert mersenne_twister.generate_number() != mersenne_twister_spliced.generate_number()

    for i in range(624):
        # Copy the internal state
        mersenne_twister_spliced.MT[i] = un_temper(mersenne_twister.generate_number(), w, b, c, d, u, s, t, l)

    mersenne_twister_spliced.twist()
    for i in range(100):
        # Owned it!
        assert mersenne_twister_spliced.generate_number() == mersenne_twister.generate_number()




if __name__ == '__main__':
    main()
