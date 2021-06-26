def pkcs7(message : bytes, blocksize : int) -> bytes:
    """Add PKCS#7 padding to message to match blocksize"""
    padding = blocksize - ( len(message) % blocksize )
    return message + bytes([padding]*padding)

def pkcs7_strip(data : bytes) -> bytes:
    """Removes PKCS#7 padding"""
    padding_length = data[-1]
    return data[:- padding_length]


if __name__ == '__main__':
    string = b"YELLOW SUBMARINE"
    print(pkcs7(string, blocksize=20))
    print(pkcs7_strip(pkcs7(string, blocksize=20)))
