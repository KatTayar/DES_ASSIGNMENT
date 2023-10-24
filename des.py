import copy
from des_constants import *
from des_keygen import get_round_keys
from des_shared import permutate


def encrypt(plaintext: str, key: int) -> str:
    """
    This function will encrypt a plaintext message using the DES algorithm.
    :param plaintext: str, message to be encrypted. ASCII.
    :param key: int, 64-bit. DES key
    :return: str, encrypted message. ASCII.
    """

    # get blocks from plaintext
    blocks = get_blocks(plaintext)

    # get round-keys from key
    round_keys = get_round_keys(key)

    cipher_text_blocks = []
    for block in blocks:
        # we copy the blocks to avoid changing the original blocks / round keys
        tmp_block = copy.copy(block)
        tmp_round_keys = copy.deepcopy(round_keys)

        encrypted_block = encrypt_block(tmp_block, tmp_round_keys)
        cipher_text_blocks.append(encrypted_block)

    ciphertext = get_text_from_blocks(cipher_text_blocks)

    return ciphertext


def encrypt_block(block: list[int], round_keys: list[list[int]]) -> list[int]:
    """
    Performs the DES encrypt operation on the specified block using the passed round keys
    :param block: list[int], 64 bits
    :param round_keys: list[list[int]]. 16 round keys, each 48 bits
    :return: list[int], 64 bits
    """

    # Perform the initial permutation (Use the provided PERMUTATION constant)
    initialPermutation(block)

    # Split the block into left and right halves (32 bits each)
    left_half = block[:32]
    right_half = block[32:]

    # Complete 16 rounds
    for round_num in range(16):
        # Store the right half in a temporary variable
        temp_right_half = right_half

        # Expand the right half to 48 bits (Use the provided EXPANSION constant)
        expanded_right_half = expansion(right_half)

        # XOR the expanded right half with the corresponding round key
        round_key = round_keys[round_num]
        result = xor(expanded_right_half, round_key)

        # Perform substitution on the result (Use the provided S_BOXES constant and the substitute function)
        substituted_result = substitute(result)

        # Perform permutation on the result (Use the provided PERMUTATION constant)
        permuted_result = permutation(substituted_result)

        # XOR the result with the left half
        left_half = xor(left_half, permuted_result)

        # The original right half becomes the new left half
        right_half = temp_right_half

    # After all 16 rounds, concatenate the right and left halves (right + left)
    final_block = right_half + left_half

    # Perform the final permutation (Use the provided PERMUTATION constant)
    encrypted_block = final_permutation(final_block)

    return encrypted_block



def encrypt_block(block: list[int], round_keys: list[list[int]]) -> list[int]:
    """
    Performs the DES encrypt operation on the specified block using the passed round keys
    :param block: list[int], 64 bits
    :param round_keys: list[list[int]]. 16 round keys, each 48 bits
    :return: list[int], 64 bits
    """
# Input block (64 bits)
block = [0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0, 1, 1, 0, 1,
         1, 0, 0, 1, 0, 0, 1, 0, 0, 1, 1, 0, 1, 0, 0, 1,
         0, 1, 1, 0, 0, 1, 0, 1, 1, 0, 0, 1, 0, 0, 1, 0,
         1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 0, 1]

# Round keys (16 round keys, each 48 bits)
round_keys = [
    [1, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 1, 0, 0, 0, 1, 0, 1, 1, 0, 1, 0, 0, 0, 1, 0, 0, 0, 1, 1, 0, 1],
    # ... (other round keys) ...
]

# Perform the initial permutation (Use the provided PERMUTATION constant)
initial_permutation(block)

# Split the block into left and right halves (32 bits each)
left_half = block[:32]
right_half = block[32:]

# Complete 16 rounds
for round_num in range(16):
    # Store the right half in a temporary variable
    temp_right_half = right_half

    # Expand the right half to 48 bits (Use the provided EXPANSION constant)
    expanded_right_half = expansion(right_half)

    # XOR the expanded right half with the corresponding round key
    round_key = round_keys[round_num]
    result = xor(expanded_right_half, round_key)

    # Perform substitution on the result (Use the provided S_BOXES constant and the substitute function)
    substituted_result = substitute(result)

    # Perform permutation on the result (Use the provided PERMUTATION constant)
    permuted_result = permutation(substituted_result)

    # XOR the result with the left half
    left_half = xor(left_half, permuted_result)

    # The original right half becomes the new left half
    right_half = temp_right_half

    # After all 16 rounds, concatenate the right and left halves (right + left)
    final_block = right_half + left_half

    # Perform the final permutation (Use the provided PERMUTATION constant)
    encrypted_block = initial_permutation(final_block)
return block


def get_blocks(text: str) -> list[list[int]]:
    """
    separates text into blocks of 64-bits. Assumes one byte for each character with ASCII encoding
    :param text: str, message
    :return: list[bytearray], list of blocks
    """

    blocks = []
    current_block = []
    for char in text:
        # convert each character into an array of bits
        char_bits = [int(x) for x in bin(ord(char))[2:]]

        # add the bits to the current block with 0-padding to ensure a full byte (8 bits) is added
        current_block += [0] * (8 - len(char_bits))
        current_block += char_bits

        # for Brennon
        if len(current_block) % 8:
            print("Problem in get_blocks function. Size not divisible by 8.")
        elif len(current_block) > 64:
            print("Problem in get_blocks function. Block size too large.")

        # append and start next block once the block size is 64
        if len(current_block) == 64:
            blocks.append(current_block)
            current_block = []

    # perform padding on the last block if necessary
    if 64 > len(current_block) > 0:
        current_block += [0, 1, 1, 1, 1, 1, 1, 1] * ((64 - len(current_block)) // 8)

    # add final block to blocks
    if len(current_block) > 0:
        blocks.append(current_block)

    return blocks


def get_text_from_blocks(blocks: list[list[int]]) -> str:
    """
    converts list of blocks into a string
    :param blocks: list[list[int]], list of 64-bit blocks
    :return: str
    """

    ciphertext = ""
    # for each block
    for block in blocks:
        # 8 bytes in each block
        for byte_num in range(8):
            byte_val = 0
            # 8 bits in each byte
            for bit_num in range(8):
                byte_val += block[byte_num * 8 + bit_num] * (2 ** (7 - bit_num))

            ciphertext += chr(byte_val)

    return ciphertext


def expand(block: list[int]) -> list[int]:
    """
    Expands block using the expansion function for DES
    :param block: list[int], 32 bits
    :return: list[int], 48 bits
    """
    new_list = block + ([0] * 16)
    return permutate(new_list, EXPANSION)


def xor(barray1: list[int], barray2: list[int]) -> list[int]:
    """
    performs bitwise xor between two bit arrays. Must have same size.
    :param barray1: list[int]
    :param barray2: list[int]
    :return: list[int]
    """
    result = [barray1[i] ^ barray2[i] for i in range(len(barray1))]
    return result


def substitute(block: list[int]) -> list[int]:
    """
    performs the DES substitution step
    :param block: list[int], 48 bits
    :return: list[int], 32bits
    """

    result = []

    # get 6-bit chunks of block
    chunks = [block[i * 6: i * 6 + 6] for i in range(8)]

    for idx, chunk in enumerate(chunks):

        # convert to s-box index
        row = chunk[0] * 2 + chunk[5]
        col = chunk[1] * 8 + chunk[2] * 4 + chunk[3] * 2 + chunk[4]
        s_box_idx = row * 16 + col

        val = S_BOXES[idx][s_box_idx]

        val_bin = [int(x) for x in bin(val)[2:]]
        val_bin = [0] * (4 - len(val_bin)) + val_bin

        # for Brennon
        if len(val_bin) != 4:
            print("Error in substitute function. result of s-box lookup is not 4bits.")

        result += val_bin

    return result

plaintext = "Hello, DES!"  # Replace with your plaintext
key = 0x133457799BBCDFF1  # Replace with your 64-bit DES key

ciphertext = encrypt(plaintext, key)
print("Encrypted Text:", ciphertext)
