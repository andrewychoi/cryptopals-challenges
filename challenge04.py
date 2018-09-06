from challenge03 import unscramble


def main():
    stripped_lines = []
    with open("4.txt") as infile:
        stripped_lines = [line.strip() for line in infile]

    best_decoded = {}
    for line in stripped_lines:
        score, key, decoded = unscramble(bytes.fromhex(line))
        best_decoded[decoded] = score

    top = sorted([(score, decoded) for decoded, score in best_decoded.items()], reverse=True)
    for entry in top[:5]:
        print(entry)


if __name__ == "__main__":
    main()
