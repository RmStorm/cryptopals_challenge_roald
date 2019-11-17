import pytest

from cryptopals_challenge_roald.crypto_lib import score_string

def test_score_string():
    assert score_string('characters') == 1
    assert score_string('charactersC') == score_string('characters')
    assert score_string('charactersC', absolute_score=True) > score_string('characters', absolute_score=True)
    assert score_string('characters ') > score_string('characters"')


if __name__ == '__main__':
    pytest.main(['test_codecs.py'])
