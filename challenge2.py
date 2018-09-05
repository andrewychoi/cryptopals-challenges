def test_2():
    to_be_xored = 0x1c0111001f010100061a024b53535009181c
    xoring = 0x686974207468652062756c6c277320657965
    result = 0x746865206b696420646f6e277420706c6179

    assert to_be_xored ^ xoring == result


def main():
    test_2()


if __name__ == "__main__":
    main()
