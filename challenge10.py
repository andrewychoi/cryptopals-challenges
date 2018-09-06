import base64

from challenge07 import encrypt_aes_ecb, decrypt_aes_ecb
from challenge09 import pkcs7_pad


def xor_bytes(bytes1: bytes, bytes2: bytes) -> bytes:
    assert len(bytes1) == len(bytes2), "Can't xor byte arrays of different lengths"
    return bytes([byte1 ^ byte2 for byte1, byte2 in zip(bytes1, bytes2)])


def encrypt_aes_cbc(plaintext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(plaintext) % 16 == 0:
        num_chunks = len(plaintext) // 16
    else:
        num_chunks = len(plaintext) // 16 + 1

    encrypted = []
    prev_cipher_chunk = None
    for i in range(0, num_chunks):
        curr_chunk = plaintext[i * 16:(i + 1) * 16]
        if len(curr_chunk) < 16:
            curr_chunk = pkcs7_pad(curr_chunk)

        if not prev_cipher_chunk:
            xored_chunk = xor_bytes(curr_chunk, iv)
        else:
            xored_chunk = xor_bytes(curr_chunk, prev_cipher_chunk)

        encrypted_chunk = encrypt_aes_ecb(xored_chunk, key)
        encrypted.append(encrypted_chunk)
        prev_cipher_chunk = encrypted_chunk
    return b"".join(encrypted)


def decrypt_aes_cbc(ciphertext: bytes, key: bytes, iv: bytes) -> bytes:
    if len(ciphertext) % 16 == 0:
        num_chunks = len(ciphertext) // 16
    else:
        num_chunks = len(ciphertext) // 16 + 1

    decrypted = []
    prev_cipher_chunk = None
    for i in range(0, num_chunks):
        curr_chunk = ciphertext[i * 16: (i + 1) * 16]

        decrypted_chunk = decrypt_aes_ecb(curr_chunk, key)

        if not prev_cipher_chunk:
            curr_plain_chunk = xor_bytes(decrypted_chunk, iv)
        else:
            curr_plain_chunk = xor_bytes(decrypted_chunk, prev_cipher_chunk)
        decrypted.append(curr_plain_chunk)
        prev_cipher_chunk = curr_chunk
    return b"".join(decrypted)


def main():
    with open("10.txt") as infile:
        lines = [line.strip() for line in infile]
    encoded_text = "".join(lines)
    ciphertext = base64.b64decode(encoded_text)
    provided_key = b"YELLOW SUBMARINE"
    iv = bytes([0x00] * 16)
    print(decrypt_aes_cbc(ciphertext, provided_key, iv))

    assert encrypt_aes_cbc(decrypt_aes_cbc(ciphertext, provided_key, iv), provided_key, iv) == ciphertext


if __name__ == "__main__":
    main()
