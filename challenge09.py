def pkcs7_pad(plaintext: bytes, block_size: int = 16) -> bytes:
    """
    Pad a plaintext to a specific block size.

    Handles case where plaintext needs no padding

    """
    if len(plaintext) % block_size == 0:
        return plaintext

    multiple = len(plaintext) // block_size + 1

    padded_length = multiple * block_size

    missing = padded_length - len(plaintext)
    pad_char = bytes([missing])

    return plaintext + missing * pad_char


def main():
    testing_plaintext = b"YELLOW SUBMARINE"
    output = b"YELLOW SUBMARINE\x04\x04\x04\x04"

    to_check = pkcs7_pad(testing_plaintext, 20)
    assert to_check == output

    # make sure we don't error on an even multiple
    assert pkcs7_pad(testing_plaintext, 16) == testing_plaintext

    # make sure we don't fail on a smaller blocksize
    assert pkcs7_pad(testing_plaintext, 5) == output

    # make sure we don't fail on a larger blocksize
    assert pkcs7_pad(testing_plaintext, 25) != testing_plaintext


if __name__ == "__main__":
    main()
