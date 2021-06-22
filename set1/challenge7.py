import base64
from Crypto.Cipher import AES

def decrypt_AES_ECB(ciphertext):
    decipher = AES.new(key, AES.MODE_ECB)
    return decipher.decrypt(ciphertext)


if __name__=='__main__':
    filename = '7.txt'
    key = b"YELLOW SUBMARINE"
    with open(filename) as f:
        ciphertext = base64.b64decode(f.read())
        print(decrypt_AES_ECB(ciphertext))
