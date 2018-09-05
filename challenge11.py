import random

from challenge7 import encrypt_aes_ecb
from challenge8 import count_identical_chunks
from challenge9 import pkcs7_pad
from challenge10 import encrypt_aes_cbc


def generate_16_random_bytes() -> bytes:
    return bytes([random.randrange(0, 0xff) for i in range(0, 16)])


def encryption_oracle(plaintext: bytes) -> bytes:
    key = generate_16_random_bytes()

    prepadding = bytes([random.randrange(0, 0xff) for i in range(0, random.randrange(5, 11))])
    postpadding = bytes([random.randrange(0, 0xff) for i in range(0, random.randrange(5, 11))])

    garbage_padded_text = b"".join([prepadding, plaintext, postpadding])
    padded_text = pkcs7_pad(garbage_padded_text)
    if random.random() > 0.5:
        # ECB
        mode = "ECB"
        ciphertext = encrypt_aes_ecb(padded_text, key)
    else:
        # CBC
        mode = "CBC"
        iv = generate_16_random_bytes()
        ciphertext = encrypt_aes_cbc(padded_text, key, iv)
    return mode, ciphertext


def detect_mode(ciphertext):
    """
    Can probably tune the threshold--will try it for a bit

    threshold_chunks is the number of chunks that need to be the same for the cipher to be
    identified as ECB.
    """
    threshold_chunks = 0
    return "ECB" if count_identical_chunks(ciphertext) > threshold_chunks else "CBC"


def main():
    right = 0
    wrong = 0
    for i in range(0, 1000):
        true_mode, ciphertext = encryption_oracle(b"A" * 100)
        # print(key)
        # print(ciphertext)
        detected_mode = detect_mode(ciphertext)
        if true_mode == detected_mode:
            right += 1
        else:
            wrong += 1
    print("Got", right, "right")
    print("Got", wrong, "wrong")


if __name__ == "__main__":
    main()
