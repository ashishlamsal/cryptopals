import base64
from itertools import tee

from challenge3 import bruteforce_single_char_xor
from challenge5 import repeating_key_xor

def pairwise(iterable):
    "s -> (s0,s1), (s1,s2), (s2, s3), ..."
    a, b = tee(iterable)
    next(b, None)
    return zip(a, b)


def get_hamming_distance(input1 :bytes, input2 : bytes)->int:
    "Returns hamming distance between two input byte string"
    
    hamming_distance = 0
    for b1, b2 in zip(input1, input2):
        # XOR two bits and calcuate its binary sum (i.e no of 1's)
        hamming_distance += sum([int(bit) for bit in bin(b1 ^ b2)[2:]])
    return hamming_distance

def break_repeating_key_xor(ciphertext):
    """Attempts to break repeating-key XOR encryption.
    """
    distances = []
    for KEYSIZE in range(2, 41):

        # Break the ciphertext into chunks the length of the keysize
        chunks = [ciphertext[i:i+KEYSIZE] for i in range(0, len(ciphertext), KEYSIZE)]

        # find scores for every pair and divide by keysize
        scores = [get_hamming_distance(p1, p2) / KEYSIZE for p1 ,p2 in pairwise(chunks)]

        distances.append({
            "average": sum(scores) / len(scores),
            "key": KEYSIZE,
        })
    
    predicted_keysize = sorted(distances, key=lambda x: x['average'])[:3]

    # Will populate with a single character as each transposed 
    # block has been single-byte XOR brute forced
    key = b''

    possible_keysize = predicted_keysize[0]['key']
    for i in range(possible_keysize):
        
        # break the ciphertext into blocks of keysize length
        block = b''
        # transpose the blocks
        for j in range(i, len(ciphertext), possible_keysize):
            block += bytes([ciphertext[j]])
        # Solve each block as if it was single-character XOR
        key += bytes([bruteforce_single_char_xor(block)['key']]) 

    return (repeating_key_xor(key, ciphertext), key)


if __name__=='__main__':
    filename = '6.txt'
    with open(filename) as f:
        ciphertext = base64.b64decode(f.read())
        plaintext, key = break_repeating_key_xor(ciphertext)
        # print(f"plaintext : {plaintext}, key : {key}")


