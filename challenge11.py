import random

from challenge7 import encrypt_aes_ecb
from challenge10 import encrypt_aes_cbc


def generate_16_random_bytes() -> bytes:
    return bytes([random.randrange(0, 0xff) for i in range(0, 16)])


def encryption_oracle(plaintext: bytes, key: bytes) -> bytes:
    prepadding = bytes([random.randrange(0, 0xff) for i in range(0, random.randrange(5, 11))])
    postpadding = bytes([random.randrange(0, 0xff) for i in range(0, random.randrange(5, 11))])

    padded_text = b"".join([prepadding, plaintext, postpadding])
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
    mode = "ECB" if random.random() < 0.5 else "CBC"
    return mode


def main():
    key = generate_16_random_bytes()
    true_mode, ciphertext = encryption_oracle(b"test", key)
    # print(key)
    # print(ciphertext)
    print("True mode:", true_mode)
    print("Detected mode:", detect_mode(ciphertext))


if __name__ == "__main__":
    main()
