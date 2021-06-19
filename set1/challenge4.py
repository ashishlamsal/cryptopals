from challenge3 import *

filename = 'set1/4.txt'

with open(filename) as f:
    content = [line.rstrip('\n') for line in f]

    result = []
    for text in content:
        bdata =bytes.fromhex(text)
        for i in range(256):
            decode = single_char_xor(bdata, i)
            score = get_english_score(decode)
            result.append((score,decode))
    
    for flag in sorted(result, key=lambda x:x[0], reverse=True)[:10]:
        print(flag)