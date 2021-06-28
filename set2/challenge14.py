import secrets
import random
from base64 import b64decode
from set1.challenge7 import encrypt_AES_ECB
from set1.challenge8 import detect_AES_ECB, find_repeating_blocks
from set2.challenge9 import pkcs7
from set2.challenge12 import block_and_padding_size, byte_at_a_time_decrypt


def encryption_oracle_ecb_v2(plaintext: bytes) -> bytes:
    '''Encrypts plaintext + secret with AES ECB.
    C = oracle (P) = ECB(R | P | S , K) where,
    K = consistent but unknown key
    S = secret string
    P = plaintext
    R = random string
    '''
    # prepend random prefix to plaintext
    plaintext = random_prefix + plaintext

    # append unknown text to plaintext
    plaintext += unknown_string

    # add padding
    plaintext = pkcs7(plaintext, blocksize=16)

    return encrypt_AES_ECB(key, plaintext)


def get_prefix_parameters(blocksize : int) -> tuple[int, int]:
    # give an increasing length input to the oracle until you fill completely
    # two blocks (ECB is used, you'll find two equal blocks in the cipher)
    filling = b'A'
    while True:
        ciphertext = encryption_oracle_ecb_v2(filling)
        blocks = find_repeating_blocks(ciphertext)
        if 2 in blocks.values():
            for b, n in blocks.items():
                if n == 2:
                    block = b
                    break
            break
        filling += b'A'

    # this is the space of its last block that is NOT used by the random prefix
    # because it doesn't match the blocksize
    fill_len = len(filling) - blocksize * 2

    # here's where the two filled blocks start (first position after the
    # "filled" blocks used by the random prefix)
    position = ciphertext.find(block+block)
    
    return position, fill_len


if __name__ == '__main__':
    random_prefix = secrets.token_bytes(random.randrange(5, 20))

    unknown_string = b64decode('''Um9sbGluJyBpbiBteSA1LjAKV2l0aCBteSByYWctdG9wIGRvd24gc28gbXkg
    aGFpciBjYW4gYmxvdwpUaGUgZ2lybGllcyBvbiBzdGFuZGJ5IHdhdmluZyBq
    dXN0IHRvIHNheSBoaQpEaWQgeW91IHN0b3A/IE5vLCBJIGp1c3QgZHJvdmUg
    YnkK''')

    # random key of 16 bytes for encryption
    key = secrets.token_bytes(16)

    # discover the block size of the cipher
    blocksize, _ = block_and_padding_size(encryption_oracle_ecb_v2)
    assert blocksize == 16

    # detect that the function is using ECB
    assert detect_AES_ECB(encryption_oracle_ecb_v2(b'A'*60))

    # obtain the offset and padding length of prefix
    position, fill_len = get_prefix_parameters(blocksize)

    # decrypt the unknown string one byte at a time
    decrypted_text = byte_at_a_time_decrypt(
        encryption_oracle_ecb_v2, blocksize, fill_len, position)
    print(decrypted_text)
    assert decrypted_text == unknown_string
