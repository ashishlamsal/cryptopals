from pwn import xor

def repeating_key_xor(key, input_bytes) -> bytes:
    return xor(key, input_bytes).hex().encode()


if __name__=='__main__':
    data = b'''Burning 'em, if you ain't quick and nimble
    I go crazy when I hear a cymbal'''

    key = b"ICE"
    print(repeating_key_xor(key,data))

