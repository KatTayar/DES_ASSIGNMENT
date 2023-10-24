from des_shared import permutate
from des_constants import *


def get_round_keys(base_key: int) -> list[list[int]]:
    """
    returns the 16 round keys for DES derived from key
    :param base_key: int, 64-bit original key
    :return: list[bytearray], list of 16 round keys 48 bits each
    """

    round_keys = []

    # convert to list of bits (64)
    base_key = [int(x) for x in bin(base_key)[2:]]
    base_key = [0] * (64 - len(base_key)) + base_key

    # remove the 8 parity bits
    reduced_base = permutate(base_key, PERM_CHOICE_1, size=56)

    # get left and right half
    left = reduced_base[:28]
    right = reduced_base[28:]

    for i in range(16):
        # left-shift the left and right half
        shift_amt = KEY_SHIFT[i]

        left = left[shift_amt:] + left[:shift_amt]
        right = right[shift_amt:] + right[:shift_amt]

        tmp = left + right

        round_keys.append(permutate(tmp, PERM_CHOICE_2, size=48))

    return round_keys

