import secrets
import random
from set1.challenge7 import encrypt_AES_ECB
from set1.challenge8 import detect_AES_ECB
from set2.challenge9 import pkcs7
from set2.challenge10 import encrypt_AES_CBC


def encryption_oracle(plaintext):
    # random key of 16 bytes for encryption
    key = secrets.token_bytes(16)

    # add extra random bytes before and after plaintext
    extra_header = secrets.token_bytes(random.randrange(5,10)) 
    extra_footer =  secrets.token_bytes(random.randrange(5,10)) 
    plaintext = extra_header + plaintext + extra_footer
    
    # add padding
    plaintext = pkcs7(plaintext, blocksize=len(key))

    # randomly choose encryption mode (ECB or CBC)
    if random.choice([0,1]):
        return encrypt_AES_ECB(key, plaintext), 'ECB'
    else:
        # random initialization vector for CBC mode encryption
        IV = secrets.token_bytes(16)
        return encrypt_AES_CBC(key, IV, plaintext), 'CBC'


def detect_AES(plaintext):
    ciphertext, mode = encryption_oracle(plaintext)
    is_ECB = detect_AES_ECB(ciphertext)

    # if detected correctly (ECB for ECB and not ECB for CBC)
    if (mode=='ECB' and is_ECB) or (mode=='CBC' and not is_ECB):
        return 0
    # if encryption was CBC but ECB detected (false positive)
    if is_ECB and mode=='CBC':
        return 1
    # if encryption was ECB but not detected (not detected)
    if not is_ECB and mode=='ECB':
        return 2


def attempt_detection(text_length, trials):
    plaintext = b'A' * text_length
    stats = [0,0,0]

    for i in range(int(trials)):
        stats[detect_AES(plaintext)] += 1

    print(f"SUCCESS: {stats[0]} \nDETECTED-WRONG: {stats[1]}\nNOT-DETECTED:{stats[2]}")
    print(f"TOTAL FAILURES: {trials - stats[0]} \nTRIALS:{ trials } \nSUCCESS PERCENT:{stats[0]/trials*100}%")


if __name__=='__main__':
    attempt_detection(42,100)