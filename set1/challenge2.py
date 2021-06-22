def XOR(first_byte: bytes, second_byte: bytes) -> bytes:
    """Takes two byte string and returns their XOR"""
    result = b''
    for bit1, bit2 in zip(first_byte, second_byte):
        result += bytes([bit1 ^ bit2])
    return result.hex().encode()


if __name__ == '__main__':
    hex_string1 = "1c0111001f010100061a024b53535009181c"
    hex_string2 = '686974207468652062756c6c277320657965'
    print(XOR(bytes.fromhex(hex_string1), bytes.fromhex(hex_string2)))
