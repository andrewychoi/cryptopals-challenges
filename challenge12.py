import base64

from challenge06 import get_scored_keysizes
from challenge07 import encrypt_aes_ecb
from challenge09 import pkcs7_pad
from challenge10 import encrypt_aes_cbc
from challenge11 import generate_16_random_bytes, detect_mode

consistent_key = generate_16_random_bytes()


def encryption_oracle(plaintext: bytes) -> bytes:
    encoded_to_append = "Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkgaGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBqdXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUgYnkK"  # noqa
    to_append = base64.b64decode(encoded_to_append)
    garbage_padded_text = b"".join([plaintext, to_append])

    padded_text = pkcs7_pad(garbage_padded_text)
    # if random.random() >= 0:
    if True:
        # ECB
        mode = "ECB"
        ciphertext = encrypt_aes_ecb(padded_text, consistent_key)
    else:
        # CBC
        mode = "CBC"
        iv = generate_16_random_bytes()
        ciphertext = encrypt_aes_cbc(padded_text, consistent_key, iv)
    return ciphertext


def main():
    injecting = b"A" * 1000
    ciphertext = encryption_oracle(injecting)
    scores = get_scored_keysizes(ciphertext, 4)
    print("With a text of length", len(injecting), "most likely keysize is", scores[0][1], "and top score is", scores[0][0])

    ciphertext = encryption_oracle(b"A" * 1000)
    print("Detected block mode:", detect_mode(ciphertext))

    chars_as_bytes = [bytes([i]) for i in range(0, 0xff + 1)]
    decrypted_chars = []
    just_encrypted = encryption_oracle(b"")

    # block_size = len(just_encrypted)
    block_size = 16
    injection_string = b"A" * (block_size - 1)

    # TODO: figure out what is happening with the -5
    for i in range(0, len(just_encrypted) - 5):
        curr_block = i // block_size
        # if i % 16 == 0:
        # injection_string = b"A" * (block_size - 1)

        # negative index to ensure that we keep injecting more ciphertext
        # inelegant solution--should be fixable
        # if i != 0:
        if i % 16 != 0:
            true_ciphertext = encryption_oracle(injection_string[:-i])
        else:
            true_ciphertext = encryption_oracle(injection_string)

        candidate_ciphertexts = {}
        for curr_char in chars_as_bytes:
            # print(curr_char)
            for_oracle = injection_string + curr_char
            # print(for_oracle)
            ciphertext = encryption_oracle(for_oracle)
            candidate_ciphertexts[ciphertext[:block_size]] = curr_char

        # start_index = block_size * curr_block + max(0, i - block_size)
        # end_index = block_size * (curr_block + 1) + max(0, i - block_size)

        start_index = block_size * curr_block
        end_index = block_size * (curr_block + 1)

        print(start_index, ":", end_index)
        check_from_true = true_ciphertext[start_index:end_index]
        print(injection_string)
        assert check_from_true in candidate_ciphertexts.keys()
        decrypted_char = candidate_ciphertexts[check_from_true]
        decrypted_chars.append(decrypted_char)
        print(b"".join(decrypted_chars))
        # now update the injection string
        # remove the first char of noise, append the new char that's known
        injection_string = injection_string[1:] + decrypted_char


if __name__ == "__main__":
    main()
