from challenge09 import pkcs7_pad
from challenge10 import encrypt_aes_cbc, decrypt_aes_cbc, xor_bytes
from challenge11 import generate_16_random_bytes


consistent_key = generate_16_random_bytes()
consistent_iv = generate_16_random_bytes()

# pulling these strings out here for convenience' sake
# yes, that's where you put the apostrophe
prepend = b"comment1=cooking%20MCs;userdata="
append = b";comment2=%20like%20a%20pound%20of%20bacon"
admin_true = b";admin=true;"


def cbc_oracle(plaintext: bytes) -> bytes:
    sanitized_plaintext = plaintext.replace(b";", b"\";\"").replace(b"=", b"\"=\"")
    total = b"".join([prepend, sanitized_plaintext, append])
    padded_total = pkcs7_pad(total)
    return encrypt_aes_cbc(padded_total, consistent_key, consistent_iv)


def decrypt_oracle(ciphertext: bytes) -> bytes:
    decrypted = decrypt_aes_cbc(ciphertext, consistent_key, consistent_iv)
    return decrypted


def main():
    """
    Attack currently limited to block_size character injections
    """
    ciphertext = cbc_oracle(admin_true)
    assert admin_true not in decrypt_oracle(ciphertext)

    block_size = 16
    prepend_length = len(prepend)
    # second mod is necessary to avoid issue with prepend_length == block_size
    prepend_padding_length = (block_size - prepend_length % block_size) % block_size
    prepend_padding = b"\x00" * prepend_padding_length
    attack_block_idx = prepend_length // block_size + (1 if prepend_padding_length != 0 else 0)

    first_attack_block = b"\x00" * block_size
    second_attack_block = b"\x00" * block_size

    attack_inject = b"".join([prepend_padding, first_attack_block, second_attack_block])
    raw_ciphertext = cbc_oracle(attack_inject)
    crafted_ciphertext = bytearray(raw_ciphertext)
    cipher_inject = xor_bytes(
        raw_ciphertext[attack_block_idx * block_size:(attack_block_idx + 1) * block_size],
        admin_true + b"\x00" * (len(first_attack_block) - len(admin_true))
    )
    crafted_ciphertext[attack_block_idx * block_size:(attack_block_idx + 1) * block_size] = cipher_inject

    crafted_plaintext = decrypt_oracle(bytes(crafted_ciphertext))
    print(crafted_plaintext)
    assert admin_true in crafted_plaintext


if __name__ == "__main__":
    main()
