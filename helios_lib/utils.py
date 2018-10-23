"""
Utilities.

Ben Adida - ben@adida.net
2005-04-11
"""

import random


random.seed()


def random_string(length=20, alphabet=None):
    random.seed()
    ALPHABET = alphabet or 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789'
    r_string = ''
    for i in range(length):
        r_string += random.choice(ALPHABET)

    return r_string
