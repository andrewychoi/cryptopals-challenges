import base64
import random

from challenge7 import encrypt_aes_ecb, decrypt_aes_ecb
from challenge9 import pkcs7_pad
from challenge11 import generate_16_random_bytes

"""
AES-128-ECB(random-prefix || attacker-controlled || target-bytes, random-key)
"""
consistent_key = generate_16_random_bytes()

# select up to block_size random bytes
prepend = generate_16_random_bytes()[:random.randint(0, 16 + 1)]


def encryption_oracle(plaintext: bytes) -> bytes:
    encoded_to_append = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"  # noqa
    to_append = base64.b64decode(encoded_to_append)
    garbage_padded_text = b"".join([prepend, plaintext, to_append])

    padded_text = pkcs7_pad(garbage_padded_text)
    ciphertext = encrypt_aes_ecb(padded_text, consistent_key)
    return ciphertext


def main():
    """
    Strategy: to find the prepended string's length, we will start with
    2 * block_size chars, and begin adding until we find two blocks that are the
    same. We then know that the prepended randomness is:
    block_size - (success_len - 2 * block_size)
    Then we proceed as before.

    """
    block_size = 16
    prepended_size_checker = b"A" * block_size * 2
    ciphertext = encryption_oracle(prepended_size_checker)
    found_identical_blocks = ciphertext[:block_size] == ciphertext[block_size:2 * block_size]
    while not found_identical_blocks:
        prepended_size_checker += b"A"
        ciphertext = encryption_oracle(prepended_size_checker)
        # since we know there's more than one byte of padding, need to check blocks 2 and 3
        found_identical_blocks = ciphertext[block_size:2 * block_size] == ciphertext[2 * block_size:3 * block_size]

    prepend_length = block_size - (len(prepended_size_checker) - 2 * block_size)
    print(prepend_length)

    print(decrypt_aes_ecb(ciphertext, consistent_key))
    print(len(decrypt_aes_ecb(ciphertext, consistent_key).split(b"A")[0]))


if __name__ == "__main__":
    main()
