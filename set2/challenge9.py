def PKCS_7(length, message):
    padding = length - len(message)
    return message + bytes([padding]*padding) if length > len(message) else message


if __name__ == '__main__':
    string = b"YELLOW SUBMARINE"
    print(PKCS_7(20, string))
