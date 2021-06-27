from set2.challenge9 import pkcs7_strip

if __name__ == '__main__':
    string1 = b"ICE ICE BABY\x04\x04\x04\x04"
    string2 = b"ICE ICE BABY\x05\x05\x05\x05"
    string3 = b"ICE ICE BABY\x01\x02\x03\x04"

    print(pkcs7_strip(string1))
    print(pkcs7_strip(string2))
    print(pkcs7_strip(string3))
    