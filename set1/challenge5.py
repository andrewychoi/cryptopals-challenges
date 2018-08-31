import base64
import itertools


def encrypt(plaintext, key):
    # for plaintext_byte, key_byte in zip(plaintext, itertools.cycle(key)):
    #     print(plaintext_byte ^ key_byte, plaintext_byte, key_byte, bytes([plaintext_byte]), bytes([key_byte]))

    encrypted = bytes([
        plaintext_byte ^ key_byte for plaintext_byte, key_byte in zip(plaintext, itertools.cycle(key))
    ])
    return encrypted


def main():
    plaintext = b"Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal"
    key = b"ICE"
    target = "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"

    encrypted = encrypt(plaintext, key)
    assert encrypted == bytes.fromhex(target)


if __name__ == "__main__":
    main()
