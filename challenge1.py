import base64


def hex_to_base64(hex_string: str) -> bytes:
    return base64.b64encode(bytes.fromhex(hex_string))


def test_1():
    hex_string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    b64_out = b"SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    assert hex_to_base64(hex_string) == b64_out


def main():
    test_1()


if __name__ == "__main__":
    main()
