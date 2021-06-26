import base64
from Crypto.Cipher import AES

def decrypt_AES_ECB(key, ciphertext):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.decrypt(ciphertext)

def encrypt_AES_ECB(key, plaintext):
    cipher = AES.new(key, AES.MODE_ECB)
    return cipher.encrypt(plaintext)

if __name__=='__main__':
    filename = 'text/7.txt'
    key = b"YELLOW SUBMARINE"
    with open(filename) as f:
        ciphertext = base64.b64decode(f.read())
        result = decrypt_AES_ECB(key, ciphertext)
        print(result)

        # test encrypt function
        assert encrypt_AES_ECB(key, result) == ciphertext

