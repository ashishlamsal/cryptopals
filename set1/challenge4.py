from challenge3 import *

filename = '4.txt'
with open(filename) as f:
    content = [line.rstrip('\n') for line in f]

    result = []
    for text in content:
        bdata = bytes.fromhex(text)
        result.append(bruteforce_single_char_xor(bdata))

    print(sorted(result, key=lambda x: x['score'], reverse=True)[0])
