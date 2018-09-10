import base64
import random

from challenge06 import get_scored_keysizes
from challenge07 import encrypt_aes_ecb, decrypt_aes_ecb
from challenge09 import pkcs7_pad
from challenge11 import generate_16_random_bytes, detect_mode

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
    print("Detected prepended length is:", prepend_length)

    injecting = b"A" * 1000
    ciphertext = encryption_oracle(injecting)
    scores = get_scored_keysizes(ciphertext, 4)
    print("With a text of length", len(injecting), "most likely keysize is", scores[0][1], "and top score is", scores[0][0])

    ciphertext = encryption_oracle(injecting)
    print("Detected block mode:", detect_mode(ciphertext))

    chars_as_bytes = [bytes([i]) for i in range(0, 0xff + 1)]
    decrypted_chars = []
    just_encrypted = encryption_oracle(b"")
    block_size = 16
    if prepend_length > 0:
        # need to push the initial noise into a first full block
        injection_string = b"A" * (block_size - prepend_length)
    else:
        injection_string = b""
    padding_block = prepend_length > 0

    # looks like the padding changes in true_ciphertext when the length of the injection string changes
    for i in range(0, len(just_encrypted)):
        if padding_block:
            # if we have padding, then we need to pad it out in the injection
            curr_block = i // block_size + 1
        else:
            curr_block = i // block_size

        if i % block_size == 0:
            injection_string = b"A" * (block_size - 1) + injection_string
        else:
            injection_string = injection_string[1:]

        # negative index to ensure that we keep injecting more ciphertext
        # inelegant solution--should be fixable
        if i != 0:
            true_ciphertext = encryption_oracle(injection_string[:-i])
        else:
            true_ciphertext = encryption_oracle(injection_string)

        candidate_ciphertexts = {}
        for curr_char in chars_as_bytes:
            for_oracle = injection_string + curr_char
            ciphertext = encryption_oracle(for_oracle)
            candidate_ciphertexts[ciphertext[block_size * curr_block:block_size * (curr_block + 1)]] = curr_char

        start_index = block_size * curr_block
        end_index = block_size * (curr_block + 1)

        check_from_true = true_ciphertext[start_index:end_index]
        # assert check_from_true in candidate_ciphertexts.keys()
        if (check_from_true in candidate_ciphertexts):
            decrypted_char = candidate_ciphertexts[check_from_true]
            decrypted_chars.append(decrypted_char)
            print(b"".join(decrypted_chars))
        # now update the injection string
        # append the new char that's known
        injection_string = injection_string + decrypted_char

    ciphertext = encryption_oracle(b"A")

    print("=" * 16)
    print("True decrypted text:")
    print(decrypt_aes_ecb(ciphertext, consistent_key))
    print("True length of prepend:", len(decrypt_aes_ecb(ciphertext, consistent_key).split(b"A")[0]))


if __name__ == "__main__":
    main()
