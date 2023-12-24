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
from tkinter import filedialog as fd

'''
Function to derive bytes key from Point key
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
    print("keyHex", keyHex)
    if len(keyHex) < 128: keyHex = keyHex + '0'*(128 - len(keyHex))
    keyBytes = bytes.fromhex(keyHex)
    print("keyBytes", keyBytes)
    derived = hkdf.derive(keyBytes)
    return derived

'''
Function to encrypt a message with a given sharedKey
'''
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

'''
Function to decrypt a message with a given sharedKey
'''
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
Functions to generate key pairs
'''
curve = registry.get_curve('brainpoolP256r1')

def getPubKey(privKey):
    global curve
    return privKey * curve.g

def genPrivKey():
    return secrets.randbelow(curve.field.n) 

'''
Function to generate fernetKey for decrypting stored .key files using password and salt
'''
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

'''
Function storing a private key to a file
'''
def storeKeyToFile(privKey, fernetKey, filename):
    fernet = Fernet(fernetKey)
    encryptedPrivKey = fernet.encrypt(str(privKey).encode('utf-8'))
    with open(filename, 'wb') as file:
        file.write(encryptedPrivKey)

'''
Function retrieving a private key from a file
'''
def getKeyFromFile(fernetKey, filename):
    fernet = Fernet(fernetKey)
    with open(filename, 'rb') as file:
        privKeyBytes = file.read()
    decryptedPrivKey = fernet.decrypt(privKeyBytes).decode('utf-8')
    decryptedPrivKey = int(decryptedPrivKey)
    return decryptedPrivKey

'''
Convert from Point object to JSON string and back
'''
def pointToJSON(point):
    d = {'x': point.x, 'y': point.y}
    return json.dumps(d)

def JSONtoPoint(jsonstr):
    global curve
    d = json.loads(jsonstr)
    point = ec.Point(curve, d['x'], d['y'])
    return point

'''
Convert from bytes to base64 string and back
'''
def bytesToB64(bytes):
    return base64.b64encode(bytes).decode('utf-8')

def b64toBytes(b64):
    return base64.b64decode(b64)

'''
Convert from file to base64 string and back
'''

def fileToB64(path):
    with open(path, 'rb') as file:
        encoded = base64.b64encode(file.read())
    return encoded.decode()

def B64toFile(b64, outputPath):
    decoded = base64.b64decode(b64)
    with open(outputPath, 'wb') as file:
        file.write(decoded)