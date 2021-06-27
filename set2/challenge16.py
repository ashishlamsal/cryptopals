import secrets
from set1.challenge5 import repeating_key_xor
from set2.challenge10 import encrypt_AES_CBC, decrypt_AES_CBC
from set2.challenge9 import pkcs7


def encrypt(plaintext):
    plaintext = plaintext.replace(b";", b'";"').replace(b"=",  b'"="')
    # plaintext = b"comment1=cooking%20MCs;userdata=" + plaintext
    plaintext = b"comment1=cooking%20M" + plaintext
    plaintext += b";comment2=%20like%20a%20pound%20of%20bacon"
    return encrypt_AES_CBC(key, IV, pkcs7(plaintext, blocksize=16))


def decrypt(ciphertext):
    return decrypt_AES_CBC(key, IV, ciphertext)


def print_blocks(buf: bytes, bsize: int=16):
    """print_blocks: print the buffer "buf" with  separator character "|" every
    "bsize" bytes.

    :param buf: the buffer
    :type buf: bytes
    :param bsize: the block size
    :type bsize: int
    """
    if len(buf)%bsize != 0:
        raise ValueError
    for i in range(len(buf)//bsize):
        print(buf[bsize*i:bsize*i+bsize], end='|')
    print()


def count_consecutive_zeros(buf: bytes) -> int:
    """count_consecutive_zeros: count the consecutive zeros starting from
    position 0 in the buffer.
    Return the number of consecutive zeros.

    :param buf: the buffer
    :type buf: bytes

    :rtype: int
    """
    count = 0
    for i in buf:
        if i != 0:
            break
        else:
            count += 1
    return count


def get_prefix_parameters(blocksize) -> tuple[int, bytes]:
    '''
    Returns no. of blocks occupied by padding.
    Returns required padding to adjust the prefix

    if len(prefix) % blocksize == 0, then pads entire next block       
    if len(prefix) % blocksize != 0, then pads partially used prefix block       
    '''
    # start with an empty input 
    padding = b''
    current_ciphertext = encrypt(padding)
    
    # add a byte and find the difference
    padding += b'a'
    next_ciphertext = encrypt(padding)

    # XOR results in 0's upto same values of two inputs (i.e. length of prefix)
    xored_ciphertext = repeating_key_xor(current_ciphertext, next_ciphertext)
    
    #  get the number of complete blocks are used by the random prefix
    complete_prefix_bytes = count_consecutive_zeros(xored_ciphertext)
    complete_prefix_blocks = complete_prefix_bytes // blocksize

    current_ciphertext = next_ciphertext
    while True:
        padding += b'a'
        next_ciphertext = encrypt(padding)
        xored_ciphertext = repeating_key_xor(current_ciphertext, next_ciphertext)
        
        # get no. of blocks and bytes that are not changed from the previous input
        zero_bytes = count_consecutive_zeros(xored_ciphertext)
        zero_blocks = zero_bytes//blocksize
    
        # if we filled another block we have to stop
        if zero_blocks - complete_prefix_blocks >= 1:
            padding = padding[:-1]
            break
        current_ciphertext = next_ciphertext

    '''
    if padding is of 16 bytes then random prefix was a multiple
    of the blocksize and we already have one "empty block"
    otherwise we just filled a partially used prefix block 
    by padding and we need to add the "empty block"  
    '''    
    if len(padding) != blocksize:
        complete_prefix_blocks +=1
        padding += b'a' * blocksize
    
    print(f'[+] Added { len(padding) } bytes padding')
    
    return complete_prefix_blocks, padding 
    

if __name__ == "__main__":
    blocksize = 16
    IV = secrets.token_bytes(blocksize)
    key = secrets.token_bytes(blocksize)

    # prefix block to step through and padding added to adjust prefix
    prefix_offset, padding = get_prefix_parameters(blocksize)

    # craft target block, 'X' are placeholder for forbidden characters 
    dummy = b'X'
    target = b'aaaaa' + dummy + b'admin' + dummy + b'true'

    # the offsets of the forbidden characters 
    p1 = prefix_offset*blocksize + 5
    p2 = prefix_offset*blocksize + 11

    # ... | block i             | block i+1        | block i+2        | ...
    # ... | last prefix block   | aaaaaaaaaaaaaaaa | aaaaaXadminXtrue | ...
    plaintext = padding + target

    # get the ciphertext for crafted paintext
    ciphertext = bytearray(encrypt(plaintext))

    # change the bits of ciphertext to inject ';' and '='
    ciphertext[p1] = ciphertext[p1] ^ ord(dummy) ^ ord(';')
    ciphertext[p2] = ciphertext[p2] ^ ord(dummy) ^ ord('=')

    # check if we got the desired string in the plaintext
    decrypted = decrypt(bytes(ciphertext))
    if b";admin=true;" in decrypted:
        print('[+] CBC bitflipping attack successful.\n[+] ";admin=true;" flag passed.')
    else:
        print('[-] CBC bitflipping attack failed.')

