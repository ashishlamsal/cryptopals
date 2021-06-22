

if __name__=='__main__':
    filename = '8.txt'
    with open(filename) as f:
        hexdata = [line.rstrip('\n') for line in f]

        result =[]
        for text in hexdata:
            ciphertext = bytes.fromhex(text)

            # Group the data and count repeating chunks
            # ciphertext that has max repeatiting chunks is AES ECB encrypted
            block_size = 16

            # break the string into block_size chunks
            chunks = [ciphertext[i:i+block_size] for i in range(0, len(ciphertext), block_size)]

            result.append({
                "ciphertext": ciphertext,
                "repeatitions": len(chunks) - len(set(chunks)),
            })

        most_repetitions = sorted(result, key=lambda x: x["repeatitions"], reverse=True)[0]
        print(most_repetitions)

