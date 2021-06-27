def pkcs7(message : bytes, blocksize : int) -> bytes:
    """Add PKCS#7 padding to message to match blocksize"""
    padding = blocksize - ( len(message) % blocksize )
    return message + bytes([padding]*padding)


def pkcs7_strip(data : bytes) -> bytes:
    """Removes PKCS#7 padding"""
    # get the last padding value
    padding_value = data[-1]

    # find number of padding_value in reversed data
    pading_length = data.count(data[-1:], -padding_value)
    
    # check if the number of padding_value matches padding_length
    if pading_length != padding_value:
        raise ValueError("Error Unpacking PKCS#7")

    return data[:- padding_value]


if __name__ == '__main__':
    string = b"YELLOW SUBMARINE"
    print(pkcs7(string, blocksize=20))
    print(pkcs7_strip(pkcs7(string, blocksize=20)))
