import secrets
from base64 import b64decode
from set1.challenge7 import encrypt_AES_ECB
from set1.challenge8 import detect_AES_ECB
from set2.challenge9 import pkcs7


def encryption_oracle_ecb_v1(plaintext : bytes) -> bytes:
    '''Encrypts plaintext + secret with AES ECB.
    C = oracle (P) = ECB(P | S , K) where, K = consistent but unknown
    '''
    # append unknown text to plaintext
    plaintext += unknown_string

    # add padding
    plaintext = pkcs7(plaintext, blocksize=16)

    return encrypt_AES_ECB(key, plaintext)


def block_and_padding_size(oracle, fill_length=0):
    """Returns a tuple of int containing the block size and the length of padding
    """
    blocksize_limit = 64
    blocksize = 0
    
    plaintext = b'A' * fill_length
    ct_len = len(oracle(plaintext))

    for i in range(blocksize_limit + 1):
        plaintext += b'A'
        ciphertext = oracle(plaintext)
        if len(ciphertext) != ct_len:
            blocksize = len(ciphertext) - ct_len
            break

    return blocksize, i+1


def create_dictionary(oracle, blocksize: int, fill=b'') -> dict:
    """Dictionary of plaintext and ciphertext"""
    ct_store = {}
    for i in range(blocksize):
        plaintext = fill + b'A'* (blocksize-1-i)
        ciphertext = oracle(plaintext)
        ct_store[i] = {}
        ct_store[i]['C'] = ciphertext
        ct_store[i]['P'] = plaintext

    return ct_store


def byte_at_a_time_decrypt(oracle, blocksize: int, fill_length =0, offset =0) -> bytes:    
    # fill the last block used by the random prefix to reach a full bsize block
    fill = b'A' * fill_length
     
    # compute how many blocks we have to crack (plaintext = secret + padding)
    ciphertext = oracle(fill + b'')
    if len(ciphertext) % blocksize != 0: raise ValueError("Error: decryption not possible")
    n_blocks = len(ciphertext) // blocksize
    
    # subtract the blocks used by the random prefix
    n_blocks = n_blocks - offset// blocksize

    # get the length of the secret text
    blocksize, padding = block_and_padding_size(oracle, fill_length)
    s_length = len(ciphertext) - padding - offset

    # plaintexts (P_n) and their corresponding ciphertexts(C_n)
    ct_store = create_dictionary(oracle, blocksize, fill)

    # store the recovered bytes
    recovered = b''

    # decrypt one block at a time
    for b in range(n_blocks):

        # cycle through every byte in the block
        for i in range(blocksize):
            
            # try every possible value [0, 255] in one byte
            for k in range(256):
                # craft the input using the current plaintext, the bytes
                # recovered so far and the current test value
                crafted_input = ct_store[i]['P'] + recovered + bytes([k])
                
                # get the ciphertext using the crafted input
                cipher_crafted = oracle(crafted_input)
                
                # check if the b-th blocks of the two ciphers match
                if (cipher_crafted[b*blocksize+offset:b*blocksize+offset+blocksize] ==
                        ct_store[i]['C'][b*blocksize+offset:b*blocksize+offset+blocksize]):
                    
                    # if they match, we got a new byte. store it
                    recovered += bytes([k])

                    # check if we recovered all the characters
                    if len(recovered) == s_length:
                        return recovered
                    
                    # exit the bruteforce loop
                    break



if __name__ == '__main__':
    unknown_string = b64decode('''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK''')

    # random key of 16 bytes for encryption
    key = secrets.token_bytes(16)

    # discover the block size of the cipher
    blocksize, _ = block_and_padding_size(encryption_oracle_ecb_v1)
    assert blocksize == 16

    # detect that the function is using ECB
    assert detect_AES_ECB(encryption_oracle_ecb_v1(b'A'*60))

    # decrypt the unknown string one byte at a time
    decrypted_text = byte_at_a_time_decrypt(encryption_oracle_ecb_v1, blocksize)
    print(decrypted_text)
    assert decrypted_text == unknown_string

