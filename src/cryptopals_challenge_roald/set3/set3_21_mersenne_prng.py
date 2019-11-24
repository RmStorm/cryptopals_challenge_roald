class MersenneTwister():
    def __init__(self):
        self.set_to_32_bits()

    def set_to_32_bits(self):
        self.w = 32  # word size (in number of bits)
        self.n = 624  # degree of recurrence
        self.m = 397  # middle word, an offset used in the recurrence relation defining the series x, 1 ≤ m < n
        self.r = 31  # separation point of one word, or the number of bits of the lower bitmask, 0 ≤ r ≤ w - 1
        self.a = 0x9908B0DF  # coefficients of the rational normal form twist matrix
        self.b, self.c = 0x9D2C5680, 0xEFC60000  # TGFSR(R) tempering bitmasks
        self.s, self.t = 7, 15  # TGFSR(R) tempering bit shifts
        self.u, self.d, self.l = 11, 0xFFFFFFFF, 18  # additional Mersenne Twister tempering bit shifts/masks
        self.f = 1812433253  # parameter for use in seeding
        self.reset()

    def set_to_64_bits(self):
        self.w = 64
        self.n = 312
        self.m = 156
        self.r = 31
        self.a = 0xB5026F5AA96619E9
        self.b, self.c = 0x71D67FFFEDA60000, 0xFFF7EEE000000000
        self.s, self.t = 17, 37
        self.u, self.d, self.l = 29, 0x5555555555555555, 43
        self.f = 6364136223846793005
        self.reset()

    def reset(self):
        self.MT = [0] * self.n
        self.current_index = self.n + 1

        self.word_mask = int('1'*self.w, 2)
        self.lower_mask = (1 << self.r) - 1
        self.upper_mask = self.word_mask & (~self.lower_mask)
        # print(f'lower = {self.lower_mask:064b}\nupper = {self.upper_mask:064b}')
        # print(f'lower = {self.lower_mask:016x}\nupper = {self.upper_mask:016x}')
        # print(f'word_mask = {self.word_mask:016x}')


    def output_all(self):
        return self.w, self.n, self.m, self.r, self.a, self.b, self.c, self.s, self.t, self.u, self.d, self.l, self.f

    def seed(self, seed: int = 5489):
        self.current_index = self.n
        self.MT[0] = self.word_mask & seed
        for i in range(1, self.n):
            self.MT[i] = self.word_mask & (self.f * (self.MT[i - 1] ^ (self.MT[i - 1] >> (self.w - 2))) + i)

    def twist(self):
        self.current_index = 0
        for i in range(self.n):
            new_x = (self.MT[i] & self.upper_mask) + (self.MT[(i + 1) % self.n] & self.lower_mask)
            xA = new_x >> 1 if (new_x % 2) == 0 else (new_x >> 1) ^ self.a
            self.MT[i] = self.MT[(i + self.m) % self.n] ^ xA

    def generate_number(self):
        if self.current_index == self.n:
            self.twist()
        output = self.temper_output(self.MT[self.current_index])
        self.current_index += 1
        return output

    def temper_output(self, y):
        y ^= ((y >> self.u) & self.d)
        y ^= ((y << self.s) & self.b)
        y ^= ((y << self.t) & self.c)
        return self.word_mask & (y ^ (y >> self.l))


def main():
    mersenne_twister = MersenneTwister()
    mersenne_twister.seed(5489)
    print(f'{mersenne_twister.generate_number():08x}')


if __name__ == '__main__':
    main()
