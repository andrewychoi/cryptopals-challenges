import base64
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend


def encrypt_aes_ecb(plaintext, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    encryptor = cipher.encryptor()
    encrypted = encryptor.update(plaintext) + encryptor.finalize()
    return encrypted


def decrypt_aes_ecb(ciphertext, key):
    backend = default_backend()
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=backend)
    decryptor = cipher.decryptor()
    decrypted = decryptor.update(ciphertext) + decryptor.finalize()
    return decrypted


def solve_openssl(ciphertext, key):
    """
    solution using openssl
    """
    return decrypt_aes_ecb(ciphertext, key)


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
