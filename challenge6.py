import base64
import itertools
from typing import Tuple, List

from challenge3 import unscramble
from challenge5 import encrypt


def hamming_distance(first: bytes, second: bytes) -> int:
    """
    Calculate Hamming distance: count the number of bits of difference between
    two bytestrings.

    XOR the two bytestrings together, and then shift each bit to be the LSB and AND with 1
    """
    bits_diffs = []

    assert len(first) == len(second), "Incompatible lengths in Hamming distance calculation"
    for char1, char2 in zip(first, second):
        xored = char1 ^ char2
        # range goes to 9 because there are potentially 8 bits to check
        bits_diff = sum((xored >> i) & 1 for i in range(0, 9))
        bits_diffs.append(bits_diff)
    return sum(bits_diffs)


def test_hamming_distance():
    """
    Test case from docs
    """
    first = b"this is a test"
    second = b"wokka wokka!!!"
    assert hamming_distance(first, second) == 37

    # reflexivity test, just in case
    assert hamming_distance(first, second) == hamming_distance(second, first)


def get_scored_keysizes(cyphertext: bytes, num_blocks: int = 2) -> List[Tuple[float, int]]:
    assert num_blocks >= 2, "Can't score potential keysizes with less than two blocks"

    keysizes = list(range(2, 41))
    # print(keysizes)
    keysize_to_distance = {}
    for keysize in keysizes:
        chunks = []
        for block in range(0, num_blocks):
            chunks.append(cyphertext[block * keysize:(block + 1) * keysize])
        # print(chunks)
        # print(keysize)
        # for chunk in chunks:
        #   print(len(chunk))
        distances = []
        for chunk_pair in itertools.combinations(chunks, 2):
            distances.append(hamming_distance(chunk_pair[0], chunk_pair[1]))
        keysize_to_distance[keysize] = sum(distances) / len(distances)
    # print(keysize_to_distance)
    return sorted((distance / keysize, keysize) for keysize, distance in keysize_to_distance.items())


def transpose_blocks(cyphertext: bytes, keysize: int) -> List[bytes]:
    transposed = []
    for i in range(keysize):
        sliced = itertools.islice(cyphertext, i, None, keysize)
        block = b"".join(bytes([char]) for char in sliced)
        transposed.append(block)
    return transposed


def main():
    test_hamming_distance()

    lines = []
    with open("6.txt") as infile:
        for line in infile:
            lines.append(line)

    encoded_cyphertext = ''.join(lines)
    cyphertext = base64.b64decode(encoded_cyphertext)

    keysizes_to_try = set()
    for num_blocks in range(2, 5):
        scored_keysizes = get_scored_keysizes(cyphertext, num_blocks)
        top_keysizes = (keysize for score, keysize in scored_keysizes[:3])
        keysizes_to_try.update(top_keysizes)
    print(keysizes_to_try)

    transpositions = {}
    for keysize in keysizes_to_try:
        print("Trying keysize:", keysize)
        transpositions[keysize] = transpose_blocks(cyphertext, keysize)

        unscrambled = unscramble(transpositions[keysize][0])
        print(unscrambled)
        score, key, decrypted = unscrambled
        # looks like 29 feels good, it has highest score by meaningful margin
    blocks = transpose_blocks(cyphertext, keysize=29)
    key_chars = []
    transposed_decrypted = []
    for block in blocks:
        unscrambled = unscramble(block)
        score, key_char, decrypted = unscrambled
        key_chars.append(bytes([key_char]))
        transposed_decrypted.append(decrypted)
    recovered_key = b"".join(key_chars)
    print(recovered_key)
    # print(cyphertext)
    # print(b"".join(transposed_decrypted))
    # print(transpose_blocks(b"".join(transposed_decrypted), 29))
    print(encrypt(cyphertext, recovered_key))


if __name__ == "__main__":
    main()
