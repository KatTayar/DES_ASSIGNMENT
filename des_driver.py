from des import encrypt, decrypt


def get_msg_from_file(filename: str) -> str:
    """
    reads a file and returns the contents as a string. Expects ASCII encoding
    :param filename: str, name of file to read message from
    :return: str, contents of file
    """

    try:
        with open(filename) as file:
            contents = str(file.read().strip())
            print(len(contents))
    except FileNotFoundError:
        print("File not found. Returning empty string")
        return ""

    return contents


def write_msg_to_file(filename: str, message: str) -> None:
    """
    writes a str to a file.
    :param message: str, contents to write to file
    :param filename: str, name of file to write to
    """

    with open(filename, 'w') as file:
        file.write(message)


def get_key(filename: str) -> int:
    """
    Gets key from a file
    :param filename: str, name of file to read key from
    :return: int
    """

    try:
        key = int(get_msg_from_file(filename).strip())
    except ValueError:
        print("File does not contain a valid key. Returning 0.")
        return 0

    return key


def main():
    in_file = input("Enter the name of the file to read message from: ")
    message = get_msg_from_file(in_file)

    key_file = input("Enter the name of the file with the key: ")
    key = get_key(key_file)

    isEncrypt = input("Would you like to encrypt or decrypt (e/d): ").strip().lower() == 'e'

    if isEncrypt:
        result = encrypt(message, key)
    else:
        result = decrypt(message, key)

    out_file = input("Enter the name of the file to store the result: ")
    write_msg_to_file(out_file, result)

    print("Program completed.")


if __name__ == "__main__":
    main()
