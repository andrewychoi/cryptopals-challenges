import itertools


def count_identical_chunks(ciphertext, aligned=False):
    """
    returns a count of 16-byte chunks that are the same in a ciphertext

    To detect if a ciphertext is encoded via AES in ECB mode.

    Setting aligned=True speeds things up a bit, but not sure if it compromises results
    """
    if aligned:
        # aligned
        chunked = [ciphertext[i * 4:(i + 1) * 4] for i in range(0, len(ciphertext) // 4)]
    else:
        # unaligned:
        chunked = [ciphertext[i:i + 4] for i in range(0, len(ciphertext) - 4)]

    num_chunks_same = 0
    for chunk1, chunk2 in itertools.combinations(chunked, 2):
        xored = sum(char1 ^ char2 for char1, char2 in zip(chunk1, chunk2))
        if xored == 0:
            num_chunks_same += 1
    return num_chunks_same


def main():
    """
    Since we know that in ECB mode, the same 16 byte plaintext generates the same
    16 byte ciphertext, we assume we need to find a ciphertext in which there are
    two 16-byte chunks that are the same. Fastest way to do this: xor all possible
    combinations of 16-byte chunks to find if any are equal

    Questions: do the 16-byte chunks need to be aligned?
    Empirically, when trying it without the alignment, we find the same ciphertext,
    so it seems that it may be the case that they do not need to be aligned!

    """
    ciphertexts = []
    with open("8.txt") as infile:
        for line in infile:
            ciphertexts.append(bytes.fromhex(line.strip()))
    candidates = {}
    for ciphertext in ciphertexts:
        identical_chunk_count = count_identical_chunks(ciphertext, aligned=True)
        if identical_chunk_count > 0:
            candidates[ciphertext] = identical_chunk_count

    print(candidates)


if __name__ == "__main__":
    main()
