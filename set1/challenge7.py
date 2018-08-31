import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def solve_openssl(ciphertext, key):
    """
    solution using openssl
    """
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted


def main():
    lines = []
    with open("7.txt") as infile:
        for line in infile:
            lines.append(line)
    encoded_ciphertext = "".join(lines)
    ciphertext = base64.b64decode(encoded_ciphertext)
    provided_key = b"YELLOW SUBMARINE"
    print(solve_openssl(ciphertext, provided_key))


if __name__ == "__main__":
    main()
