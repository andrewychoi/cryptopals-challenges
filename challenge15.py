def main():
    # provided test cases
    test_input = b"ICE ICE BABY\x04\x04\x04\x04"
    test_output = b"ICE ICE BABY"

    assert strip_pkcs7_padding(test_input) == test_output

    invalid_inputs = [
        b"ICE ICE BABY\x05\x05\x05\x05",
        b"ICE ICE BABY\x03\x02\x01\x04",
    ]

    for invalid_input in invalid_inputs:
        try:
            strip_pkcs7_padding(invalid_input)
        except ValueError as e:
            pass
        else:
            assert False, "Invalid input failed to raise error: " + str(invalid_input)

    # my own test cases:
    test_input = b"YELLOW SUBMARINE"
    test_output = b"YELLOW SUBMARINE"
    try:
        strip_pkcs7_padding(test_input)
    except ValueError as e:
        pass
    else:
        assert False


def strip_pkcs7_padding(plaintext: bytes) -> bytes:
    block_size = 16
    if len(plaintext) % block_size != 0:
        raise ValueError("Plaintext length is not a multiple of block size")
    # autocasts to int, so no need to recast
    padding_length = plaintext[-1]
    padding = plaintext[-padding_length:]
    chars_in_padding = set(char for char in padding)
    if len(chars_in_padding) != 1:
        raise ValueError("Prospective padding is heterogeneous")
    # at this point, we know we have only one char in padding: need to make sure it's the length
    padding_char = list(chars_in_padding)[0]
    if padding_char != padding_length:
        raise ValueError("Wrong char used in padding")
    # we are safe!
    return plaintext[:-padding_length]


if __name__ == "__main__":
    main()
