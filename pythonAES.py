# argon2 (pip install argon2-cffi==21.3.0)
from argon2 import extract_parameters, low_level, Type
# pycryptodome (pip install pycryptodome==3.18.0)
from Crypto.Cipher import AES
# invisible user input
from getpass import getpass


def GetArgonHash(masterPassword, customSalt):
    # get argon2 hash (dangerous low_level needed to use custom salt!), hash_len 23 for AES256
    hash = low_level.hash_secret(secret=masterPassword, salt=customSalt, time_cost=3, memory_cost=65536, parallelism=4, hash_len=23, type=Type.ID, version=19)
    # type ID means e.g. Argon2id (which is a hybrid of Argon2i and Argon2d)
    # timecost means iteration amount

    # cast hash from bytes to string
    hash = hash.decode()
    # extract password
    argonPassword = hash.split('$')[-1]
    # fix padding (must be multiple of 4 chars) by adding required amount of =
    paddingAmount = 4 - (len(argonPassword) % 4)
    argonPassword += "=" * paddingAmount
    # convert it back to bytes
    return argonPassword.encode()

# AES-GCM-256
def AES_Encrypt(encryptionPassword, customSalt, data):
    # encryptionPassword length is 16 = AES128, 32 = AES256
    # nonce is a byte string that must never be reused for any other encryption done with this key, recommended length 16 bytes
    cipher = AES.new(key=encryptionPassword, mode=AES.MODE_GCM, nonce=customSalt)
    ciphertext, tag = cipher.encrypt_and_digest(data)   # tag will be used in decryption to ensure that data has not been tampered with
    print("\nWrite these two values down, they are required for decryption and authenticity checking:")
    print("Tag:", tag.hex())
    print("Encrypted data:", ciphertext.hex())
    return ciphertext, tag

def AES_Decrypt():
    masterPassword = getpass("Enter password: ").encode()
    customSalt = input("\nEnter salt hex in capslock without spaces (e.g. AABBCCDDEEFFAABBCCDDEEFFAABBCCDD): ").encode()
    tag = bytes.fromhex(input("Enter tag hex: "))
    ciphertext = bytes.fromhex(input("Enter encrypted message hex: "))
    
    # reconstruct argon2 hash
    encryptionPassword = GetArgonHash(masterPassword, customSalt)

    # decrypt data
    cipher = AES.new(key=encryptionPassword, mode=AES.MODE_GCM, nonce=customSalt)
    plaintext = cipher.decrypt(ciphertext)
    
    # ensure data has not been tampered with
    try:
        cipher.verify(tag)
        print("Authenticity of message has successfully been verfied.")
    except ValueError:
        print("Data has been tampered with! Decryption failed.")
        return
    
    # print decrypted data (as string)
    print("Decrypted data:", plaintext.decode(encoding='utf-8'))

def EncryptMain():
    # collect user inputs
    masterPassword = getpass("Enter password: ").encode()
    if (len(masterPassword) < 10): # < 10 to enforce decent password length (TODO: enfore more rules such as lower/upper/specialchar/number etc)
        print("ERROR: Password is too weak.\nExiting..")
        return
    masterPasswordConfirm = getpass("Confirm password: ").encode()
    if (masterPassword != masterPasswordConfirm):
        print("ERROR: Passwords do not match.\nExiting..")
        return

    customSalt = input("\nEnter block 0 of target tag as capslock hex without spaces (e.g. AABBCCDDEEFFGGHHIIJJKKLLMMNNOOPP): ").encode()
    if (len(customSalt) != 32): # != 32 length of mifare classic block 0 (hex, no spaces) that will store data
        print("ERROR: Custom salt does not have required length.\nExiting..")
        return
    customSaltConfirm = input("Confirm block 0: ").encode()
    if (customSalt != customSaltConfirm):
        print("ERROR: Blocks 0 do not match.\nExiting..")
        return

    data = input("\nEnter data to encrypt: ").encode()
    
    # Prepare encryption
    encryptionPassword = GetArgonHash(masterPassword, customSalt)
    # Encrypt
    ciphertext, tag = AES_Encrypt(encryptionPassword, customSalt, data)

def DecryptMain():
    AES_Decrypt()

EncryptMain()
# DecryptMain()

'''
Usage (just comment the one you currently do not need out):
1. EncryptMain() -> write down encrypted data and tag
2. DecryptMain() -> enter requested data

3. Write encrypted data to the mifare classic that has the block0 that you used as salt, write the tag on the card itself (with a pen) + info whats stored in the card
'''
