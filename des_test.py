import unittest
import secrets
import string
from des import encrypt, decrypt

ALPHABET = string.digits + string.ascii_letters + string.punctuation + string.whitespace


def generate_rand_str(str_len: int) -> str:
    """
    returns a random string of the specified length
    :param str_len: int
    :return: str
    """
    result = "".join([secrets.choice(ALPHABET) for i in range(str_len)])

    return result


class DESTest(unittest.TestCase):

    def test_same_message_same_result(self):

        test_passes = True
        for i in range(15):
            key = secrets.randbits(64)

            # generate random message up to 2 ** 12 characters long (2 ** 15 bits)
            m1 = generate_rand_str(secrets.randbits(12))
            m2 = m1

            encr1 = encrypt(m1, key)
            encr2 = encrypt(m2, key)

            if encr1 != encr2:
                test_passes = False

        self.assertTrue(test_passes)  # add assertion here

    def test_encr_and_decr_are_inverses(self):

        test_passes = True
        num_passed = 0
        for i in range(15):
            key = secrets.randbits(64)

            m1 = generate_rand_str(secrets.randbits(12))

            encr = encrypt(m1, key)
            decr = decrypt(encr, key)

            if decr[:len(m1)] != m1:
                test_passes = False
                print(f"Fails for message: \n{m1}\nWith a key of: \n{key}\n")
            else:
                num_passed += 1

        print(num_passed)

        self.assertTrue(test_passes)


if __name__ == '__main__':
    unittest.main()
