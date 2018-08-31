import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def main():
    lines = []
    with open("7.txt") as infile:
        for line in infile:
            lines.append(line)
    print(lines)
    provided_key = "YELLOW SUBMARINE"
    print(provided_key)

    backend = default_backend()
    key = os.urandom(32)
    iv = os.urandom(16)
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=backend)
    encryptor = cipher.encryptor()
    ct = encryptor.update(b"a secret message") + encryptor.finalize()
    decryptor = cipher.decryptor()
    decryptor.update(ct) + decryptor.finalize()


if __name__ == "__main__":
    main()
