import secrets
from set1.challenge7 import encrypt_AES_ECB, decrypt_AES_ECB
from set2.challenge9 import pkcs7, pkcs7_strip


def parse_cookie(cookie: bytes) -> dict:
    return dict(pair.split('=') for pair in cookie.decode().split('&'))


def profile_for(email: bytes) -> bytes:
    if any(i in b'&=' for i in email):
        raise ValueError("Invalid email address")

    profile = {b'email': email, b'uid': b'10', b'role': b'user'}

    encoded_profile = b''
    for k, v in profile.items():
        encoded_profile += k + b'=' + v + b'&'

    return encoded_profile[:-1]


def encrypt_profile(email: str) -> bytes:
    '''Encypts email with AES-128-ECB and PKCS#7 padding'''
    profile = profile_for(email)
    return encrypt_AES_ECB(key, pkcs7(profile, blocksize=16))


def decrypt_profile(encodedtext: bytes) -> bytes:
    '''decrypts AES-128-ECB remoces PKCS#7 padding and returns cookie'''
    decode = decrypt_AES_ECB(key, encodedtext)
    return parse_cookie(pkcs7_strip(decode))


def insert_role(role: bytes) -> dict:
    '''Uses email field to add role to profile'''

    # Step 1 : add 'admin' to beginning of next block (i.e. 16-32) [PKCS#7 padding]
    # | block 1          | block 2                                           | don't care
    # | email=AAAAAAAAAA | admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b | ...
    # no of A's = 16 - len('email=') = 10
    pad_role = pkcs7(role, blocksize=16)
    email = b'A' * 10 + pad_role
    cipher1 = encrypt_profile(email)

    # Step 2 :  add block that ends with 'role='
    # | block 1          | block 2          | don't care
    # | email=AAAAAAAAAA | AAA&uid=10@role= | ...
    # | no of A's = 32 - len('email=&uid=10&role=') = 32 -19 = 13
    cipher2 = encrypt_profile(b'A' * 13)

    # Step 3 : put the admin block in right place (in encrypted ciphertext)
    # | block 1          | block 2          | block 3                                           |
    # | email=AAAAAAAAAA | AAA&uid=10@role= | admin\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b\x0b |
    ciphertext = cipher2[:32] + cipher1[16:32]
    return decrypt_profile(ciphertext)


if __name__ == '__main__':
    key = secrets.token_bytes(16)

    cookie = b'foo=bar&baz=qux&zap=zazzle'
    print(parse_cookie(cookie))

    profile = profile_for(b"foo@bar.com")
    print(profile)

    print(insert_role(b'admin'))
