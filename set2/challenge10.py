from base64 import b64decode
from set1.challenge7 import encrypt_AES_ECB, decrypt_AES_ECB
from set1.challenge5 import repeating_key_xor

def encrypt_AES_CBC(key : bytes, IV : bytes, plaintext : bytes) -> bytes:
    # break the string into block_size chunks
    chunks = [plaintext[i:i+len(key)] for i in range(0, len(plaintext), len(key))]

    ciphertext = b""
    
    # set previous to initialization vector
    previous_block = IV
    for chunk in chunks:
        # XOR previous_block and plaintext chunk (16 bits)
        temp = repeating_key_xor(previous_block, chunk)

        # finally encrypt temp with key in ECB mode
        next_block = encrypt_AES_ECB(key, temp)

        # append block to ciphertext
        ciphertext += next_block
        
        # update previous block
        previous_block = next_block

    return ciphertext


def decrypt_AES_CBC(key : bytes, IV : bytes, ciphertext : bytes) -> bytes:
    # break the string into block_size chunks
    chunks = [ciphertext[i:i+len(key)] for i in range(0, len(ciphertext), len(key))]

    plaintext = b""
    
    # set previous to initialization vector
    previous_block = IV
    for chunk in chunks:
        # decrypt ciphertext block (16 bits) with key in ECB mode
        temp = decrypt_AES_ECB(key, chunk)

        # append decrypted block to paintext
        plaintext += repeating_key_xor(previous_block, temp)
        
        # update the previous block
        previous_block = chunk

    return plaintext


if __name__=='__main__':
    key = b'YELLOW SUBMARINE'
    IV = bytes([0]* 16)

    filename = 'text/10.txt'
    with open(filename) as f:
        ciphertext = b64decode(f.read())
        plaintext = decrypt_AES_CBC(key, IV, ciphertext)
        print(plaintext)
        
        assert encrypt_AES_CBC(key, IV, plaintext) == ciphertext
        assert decrypt_AES_CBC(key, IV, ciphertext) == plaintext