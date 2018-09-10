import base64

from challenge06 import get_scored_keysizes
from challenge07 import encrypt_aes_ecb
from challenge09 import pkcs7_pad
from challenge11 import generate_16_random_bytes, detect_mode

consistent_key = generate_16_random_bytes()


def encryption_oracle(plaintext: bytes) -> bytes:
    encoded_to_append = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"  # noqa
    to_append = base64.b64decode(encoded_to_append)
    garbage_padded_text = b"".join([plaintext, to_append])
    padded_text = pkcs7_pad(garbage_padded_text)
    ciphertext = encrypt_aes_ecb(padded_text, consistent_key)
    return ciphertext


def main():
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
    injection_string = b""

    # TODO: figure out what is happening with the -5
    # looks like the padding changes in true_ciphertext when the length of the injection string changes
    for i in range(0, len(just_encrypted)):
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
        assert check_from_true in candidate_ciphertexts.keys()
        decrypted_char = candidate_ciphertexts[check_from_true]
        decrypted_chars.append(decrypted_char)
        print(b"".join(decrypted_chars))
        # now update the injection string
        # append the new char that's known
        injection_string = injection_string + decrypted_char


if __name__ == "__main__":
    main()
