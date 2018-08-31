import base64

LOWER_VS_UPPER_RATIO = 3

# Frequency table from https://en.wikipedia.org/wiki/Letter_frequency
# Spaces are more commmon than most common letter, "e"
space_freq_table = {
    b" ": LOWER_VS_UPPER_RATIO * 1.5 * 12.702
}

# The rest of the punctuation takes the fourth spot, slightly larger than "i"
# Currently, to make this work, penalize punctuation
punctuation_freq_table = {bytes([i]): -1 for i in range(32, 64 + 1)}

lower_freq_table = {
    b"a": LOWER_VS_UPPER_RATIO * 8.167,
    b"b": LOWER_VS_UPPER_RATIO * 1.492,
    b"c": LOWER_VS_UPPER_RATIO * 2.782,
    b"d": LOWER_VS_UPPER_RATIO * 4.253,
    b"e": LOWER_VS_UPPER_RATIO * 12.702,
    b"f": LOWER_VS_UPPER_RATIO * 2.228,
    b"g": LOWER_VS_UPPER_RATIO * 2.015,
    b"h": LOWER_VS_UPPER_RATIO * 6.094,
    b"i": LOWER_VS_UPPER_RATIO * 6.966,
    b"j": LOWER_VS_UPPER_RATIO * 0.153,
    b"k": LOWER_VS_UPPER_RATIO * 0.772,
    b"l": LOWER_VS_UPPER_RATIO * 4.025,
    b"m": LOWER_VS_UPPER_RATIO * 2.406,
    b"n": LOWER_VS_UPPER_RATIO * 6.749,
    b"o": LOWER_VS_UPPER_RATIO * 7.507,
    b"p": LOWER_VS_UPPER_RATIO * 1.929,
    b"q": LOWER_VS_UPPER_RATIO * 0.095,
    b"r": LOWER_VS_UPPER_RATIO * 5.987,
    b"s": LOWER_VS_UPPER_RATIO * 6.327,
    b"t": LOWER_VS_UPPER_RATIO * 9.056,
    b"u": LOWER_VS_UPPER_RATIO * 2.758,
    b"v": LOWER_VS_UPPER_RATIO * 0.978,
    b"w": LOWER_VS_UPPER_RATIO * 2.360,
    b"x": LOWER_VS_UPPER_RATIO * 0.150,
    b"y": LOWER_VS_UPPER_RATIO * 1.974,
    b"z": LOWER_VS_UPPER_RATIO * 0.074,
}

upper_freq_table = {
    b"A": 8.167,
    b"B": 1.492,
    b"C": 2.782,
    b"D": 4.253,
    b"E": 12.702,
    b"F": 2.228,
    b"G": 2.015,
    b"H": 6.094,
    b"I": 6.966,
    b"J": 0.153,
    b"K": 0.772,
    b"L": 4.025,
    b"M": 2.406,
    b"N": 6.749,
    b"O": 7.507,
    b"P": 1.929,
    b"Q": 0.095,
    b"R": 5.987,
    b"S": 6.327,
    b"T": 9.056,
    b"U": 2.758,
    b"V": 0.978,
    b"W": 2.360,
    b"X": 0.150,
    b"Y": 1.974,
    b"Z": 0.074,
}

# Nonprintable chars and nonstandard ASCII should be penalized heavily for plaintext
other_char_table = {bytes([i]): -100 for i in (*range(0, 31 + 1), *range(127, 256))}

freq_table = {**lower_freq_table, **upper_freq_table, **punctuation_freq_table, **other_char_table}

keys = range(0, 0xff)


def unscramble(encrypted_bytes):
    """
    Use single char XOR to decode an encrypted plaintext

    Input: a bytes object that represents an encrypted hex string
    Output: tuple containing (top score, key, decrypted string)
    """
    score_by_key = {}
    for key in keys:
        decrypted = b"".join([bytes([byte ^ key]) for byte in encrypted_bytes])
        freq_score = sum(
            [freq_table[bytes([byte])] for byte in decrypted if bytes([byte]) in freq_table]
        ) / len(decrypted)
        score_by_key[key] = (freq_score, decrypted)

    top_scores = sorted([(score, key, decrypted) for key, (score, decrypted) in score_by_key.items()], reverse=True)

    # for score in top_scores[:5]:
        # print(score)
    return top_scores[0]


def main():
    encrypted = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    encrypted_bytes = bytes.fromhex(encrypted)
    print(unscramble(encrypted_bytes))


if __name__ == "__main__":
    main()
