def find_repeating_blocks(ciphertext : bytes, blocksize = 16) -> dict:
    n_blocks = len(ciphertext) // blocksize
    blocks = {}
    for i in range(0, n_blocks * blocksize, blocksize):
        blocks[ciphertext[i:i+blocksize]] = blocks.get(ciphertext[i:i+blocksize], 0) + 1
    return blocks


def detect_AES_ECB(ciphertext : bytes) -> bool:
    """
    Returns true if ciphertext is AES ECB encrypted.
    ciphertext that has repeatiting chunks is AES ECB encrypted
    """
    return any(v > 1 for v in find_repeating_blocks(ciphertext).values())


def find_ECB(hexdata: list) -> None:
    for text in hexdata:
        ciphertext = bytes.fromhex(text)
        if detect_AES_ECB(ciphertext):
            return ciphertext.hex()


if __name__ == '__main__':
    filename = 'text/8.txt'
    with open(filename) as f:
        hexdata = [line.rstrip('\n') for line in f]
        print(find_ECB(hexdata))

