def repeating_key_xor(key, input) -> bytes:
    return bytes(input[i] ^ key[i % len(key)] for i in range(len(input)))

if __name__=='__main__':
    data = b'''Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal'''

    key = b"ICE"
    print(repeating_key_xor(key,data).hex())

