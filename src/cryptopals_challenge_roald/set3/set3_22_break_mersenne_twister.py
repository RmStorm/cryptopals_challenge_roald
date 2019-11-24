import datetime as dt

from cryptopals_challenge_roald.set3.set3_21_mersenne_prng import MersenneTwister


def main():
    mersenne_twister = MersenneTwister()
    mersenne_twister.seed(int(dt.datetime.now().timestamp()))
    w, n, m, r, a, b, c, s, t, u, d, l, f = mersenne_twister.output_all()



if __name__ == '__main__':
    main()
