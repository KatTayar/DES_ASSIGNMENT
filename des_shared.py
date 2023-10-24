def permutate(block: list[int], permutation: list[int], size: int = 0) -> list[int]:
    """
    Permutates the provided block using the specified permutation. size of block should match size of permutation
    :param size: only used for key gen
    :param block: list[int]
    :param permutation: list[int]
    :return: list[int]
    """

    permutated_block = [0] * len(block)

    if size != 0:
        permutated_block = [0] * size

    for i in range(len(permutated_block)):
        permutated_block[i] = block[permutation[i] - 1]

    return permutated_block
