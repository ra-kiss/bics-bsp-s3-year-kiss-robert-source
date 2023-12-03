from tinyec import registry, ec
import secrets
import base64
import json
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.primitives import hashes

'''
Encryption, Decryption and deriving Keys
'''
def deriveKey(key):
    # Use HKDF to derive a key from the shared key
    hkdf = HKDF(
        algorithm=hashes.SHA256(),
        length=32,  # Length of the derived key (AES key size)
        salt=None,
        info=b'',
        backend=default_backend()
    )
    keyHex = format(key.x, 'x') + format(key.y, 'x')
    derived = hkdf.derive(bytes.fromhex(keyHex))
    return derived

def encrypt(msg, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    encryptor = cipher.encryptor()

    # Encode the message as bytes before encryption
    msgBytes = msg.encode('utf-8')

    # Apply PKCS7 padding to the message
    padder = PKCS7(algorithms.AES.block_size).padder()
    paddedMsg = padder.update(msgBytes) + padder.finalize()

    ciphertext = encryptor.update(paddedMsg) + encryptor.finalize()
    return ciphertext

def decrypt(ciphertext, key):
    cipher = Cipher(algorithms.AES(key), modes.ECB(), backend=default_backend())
    decryptor = cipher.decryptor()

    # Decrypt the ciphertext
    decryptedMsg = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove PKCS7 padding from the decrypted message
    unpadder = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(decryptedMsg) + unpadder.finalize()

    plaintext = plaintext.decode('utf-8')
    return plaintext


'''
Generating Key Pairs
'''
curve = registry.get_curve('brainpoolP256r1')

def getPubKey(privKey):
    global curve
    return privKey * curve.g

def genPrivKey():
    return secrets.randbelow(curve.field.n) 

'''
Storing Key in File
'''
# def storeFernetKey(filename, fernetKey):
#     with open(filename, 'wb') as file:
#         file.write(fernetKey)

def passToFernetKey(password, salt):
    passwordBytes = password.encode('utf-8')
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt.encode('utf-8'),
        iterations=10000,
        backend=default_backend()
    )
    key = kdf.derive(passwordBytes)
    return base64.urlsafe_b64encode(key)


def storeKeyToFile(privKey, fernetKey, filename):
    fernet = Fernet(fernetKey)
    encryptedPrivKey = fernet.encrypt(str(privKey).encode('utf-8'))
    with open(filename, 'wb') as file:
        file.write(encryptedPrivKey)

def getKeyFromFile(fernetKey, filename):
    fernet = Fernet(fernetKey)
    with open(filename, 'rb') as file:
        privKeyBytes = file.read()
    decryptedPrivKey = fernet.decrypt(privKeyBytes).decode('utf-8')
    decryptedPrivKey = int(decryptedPrivKey)
    return decryptedPrivKey

'''
Converting functions
'''

def pointToJSON(point):
    d = {'x': point.x, 'y': point.y}
    return json.dumps(d)

def JSONtoPoint(jsonstr):
    global curve
    d = json.loads(jsonstr)
    point = ec.Point(curve, d['x'], d['y'])
    return point

def bytesToB64(bytes):
    return base64.b64encode(bytes).decode('utf-8')

def b64toBytes(b64):
    return base64.b64decode(b64)


# aPrivKey = genPrivKey()
# bPrivKey = genPrivKey()
# aPubKey = getPubKey(aPrivKey)
# bPubKey = getPubKey(bPrivKey)
# sharedKey1 = aPrivKey * bPubKey
# sharedKey1 = deriveKey(sharedKey1)
# sharedKey2 = bPrivKey * aPubKey
# sharedKey2 = deriveKey(sharedKey2)
# encMsg = encrypt("test", sharedKey1)
# encMsg = bytesToB64(encMsg)
# decMsg = b64toBytes(encMsg)
# decMsg = decrypt(decMsg, sharedKey2)

# print(decMsg)

# # TEST
# input("\nGenerate private key A>")
# aPrivKey = genPrivKey()
# print(aPrivKey)
# testpw1 = input("\nInput password for private key A>")
# testsalt1 = input("\nInput salt for private key A>")
# aFernetKey = passToFernetKey(testpw1, testsalt1) 
# input("\nStore private key A to file>")
# storeKeyToFile(aPrivKey, aFernetKey, "aPrivKey.key")

# input("\nOther party generates private key B, in practice stored on their device>")
# bPrivKey = genPrivKey()
# input("(Key not visible to client)")



# input("\nGenerate public key A>")
# aPubKey = getPubKey(aPrivKey)
# print(aPubKey)
# print(type (aPubKey))
# input("\nOther party generates public key B, in practice stored on the database and retrieved by client>")
# bPubKey = getPubKey(bPrivKey)
# print(bPubKey)

# input("\nGenerate shared key 1 from private key A and public key B>")
# sharedKey1 = aPrivKey * bPubKey
# derivedKey1 = deriveKey(sharedKey1)
# print(derivedKey1)
# msg = input("\nInput message to send encrypted to other party>")
# encryptedMsg = encrypt(msg, derivedKey1)
# print("encryptedMsg\n", encryptedMsg)
# print("base64 string\n", base64.b64encode(encryptedMsg).decode('utf-8'))
# decodedEncryptedMsg = base64.b64decode()
# print(decodedEncryptedMsg)
# print(decodedEncryptedMsg == encryptedMsg)

# input("\nOther party generates shared key 2 from private key B and public key A>")
# sharedKey2 = aPubKey * bPrivKey
# derivedKey2 = deriveKey(sharedKey2)

# print(derivedKey2, "\nNotice that: shared key 1 == shared key 2", f'{sharedKey1 == sharedKey2}>')

# input("\nOther party decrypts message using shared key 2>")
# decryptedMsg = decrypt(encryptedMsg, derivedKey2)
# print(decryptedMsg)


