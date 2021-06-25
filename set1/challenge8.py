def detect_AES_ECB(ciphertext):
    """
    Returns true if ciphertext is AES ECB encrypted.
    ciphertext that has repeatiting chunks is AES ECB encrypted
    """
    # Group the data and count repeating chunks
    block_size = 16

    # break the string into block_size chunks
    chunks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]
    
    # count number of repeated blocks
    repeated_blocks= len(chunks) - len(set(chunks)) 

    # returns True repeated_blocks is not zero
    return bool(repeated_blocks)


def find_ECB(hexdata):
    for text in hexdata:
        ciphertext = bytes.fromhex(text)
        if detect_AES_ECB(ciphertext):
            return ciphertext.hex()


if __name__ == '__main__':
    filename = 'text/8.txt'
    with open(filename) as f:
        hexdata = [line.rstrip('\n') for line in f]
        print(find_ECB(hexdata))
