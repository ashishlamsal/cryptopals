def get_english_score(input_bytes):
    """returns the score of a message based on
    relative frequency the English characters
    """
    character_frequencies = {
        'a': .08167, 'b': .01492, 'c': .02782, 'd': .04253,
        'e': .12702, 'f': .02228, 'g': .02015, 'h': .06094,
        'i': .06094, 'j': .00153, 'k': .00772, 'l': .04025,
        'm': .02406, 'n': .06749, 'o': .07507, 'p': .01929,
        'q': .00095, 'r': .05987, 's': .06327, 't': .09056,
        'u': .02758, 'v': .00978, 'w': .02360, 'x': .00150,
        'y': .01974, 'z': .00074, ' ': .13000
    }
    return sum([character_frequencies.get(chr(byte), 0) for byte in input_bytes.lower()])


def single_char_xor(input_bytes, char_value) -> bytes:
    """Returns the result of each byte being XOR'd with a single value.
    """
    output_bytes = b''
    for byte in input_bytes:
        output_bytes += bytes([byte ^ char_value])
    return output_bytes

if __name__=='__main__':
    data="1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    bdata=bytes.fromhex(data)
    result=[]
    for i in range(256):
        decode = single_char_xor(bdata, i)
        score = get_english_score(decode)
        result.append((score,decode))

    for flag in sorted(result, key=lambda x:x[0], reverse=True)[:10]:
        print(flag)


