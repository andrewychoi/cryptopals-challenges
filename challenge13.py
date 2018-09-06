from challenge7 import encrypt_aes_ecb, decrypt_aes_ecb
from challenge9 import pkcs7_pad
from challenge11 import generate_16_random_bytes

consistent_key = generate_16_random_bytes()


def parse_querystring(qs: bytes) -> dict:
    kvs = qs.split(b"&")
    parsed = {}
    for kv in kvs:
        k, v = kv.split(b"=")
        parsed[k] = v
    return parsed


def profile_for(email: bytes) -> dict:
    # sanitize email
    clean_email = email.replace(b"&", b"")
    cleaner_email = clean_email.replace(b"=", b"")

    return {
        b"email": cleaner_email,
        b"uid": b"10",
        b"role": b"user"
    }


def create_querystring(json: dict) -> bytes:
    return b"&".join(k + b"=" + v for k, v in json.items())


def profile_oracle(email: bytes) -> bytes:
    return encrypt_aes_ecb(pkcs7_pad(create_querystring(profile_for(email))), consistent_key)


def decrypt_oracle(ciphertext: bytes) -> bytes:
    return decrypt_aes_ecb(ciphertext, consistent_key)


def main():
    testing_qs = b"foo=bar&baz=qux&zap=zazzle"
    testing_output = {
        b"foo": b"bar",
        b"baz": b"qux",
        b"zap": b"zazzle"
    }
    assert parse_querystring(testing_qs) == testing_output

    target_querystring = b"email=foo@bar.com&uid=10&role=user"
    profile_json = profile_for(b"foo@bar.com")
    profile_querystring = create_querystring(profile_json)
    assert profile_querystring == target_querystring

    profile_querystring = create_querystring(profile_for(b"foo@bar.com&role=admin"))
    assert profile_querystring != b"email=foo@bar.com&role=admin&uid=10&role=user"

    # end testing

    # now, to break!
    """
    Strategy:
    """
    # for now assume ECB and 16 byte keysize
    block_size = 16
    # mode = "ECB"
    num_blocks_padded = 1

    first_injection_size = block_size - (len(b"email=") + len(b"&uid=10&role="))
    while (first_injection_size < 0):
        num_blocks_padded += 1
        first_injection_size = block_size * num_blocks_padded - (len(b"email=") + len(b"&uid=10&role="))

    first_injection = b"0" * first_injection_size
    first_ciphertext = profile_oracle(first_injection)
    first_block = first_ciphertext[:block_size * num_blocks_padded]

    # second injection has strictly less to include, so it doesn't need the padding block calculation
    second_injection_size = block_size * (num_blocks_padded) - len(b"email=")
    second_injection = b"0" * second_injection_size + b"admin"
    second_ciphertext = profile_oracle(second_injection)
    # only use one block because it cuts off the second "role=user"
    second_block = second_ciphertext[block_size * num_blocks_padded:block_size * (num_blocks_padded + 1)]

    crafted_ciphertext = first_block + second_block
    crafted_querystring = decrypt_oracle(crafted_ciphertext)

    print(crafted_querystring)
    assert b"role=admin" in crafted_querystring


if __name__ == "__main__":
    main()
