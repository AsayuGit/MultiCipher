#!python3

# Proteger input_file
# $ python multi_protect.py -e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]
# retourne 0 si OK, 1 sinon

# Deproteger input_file 
# $ python multi_protect.py -d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem> 
# retourne 0 si OK, 1 sinon

import sys
from typing import List
from io import BufferedReader, BufferedWriter
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes
import os

def symEnc(Kc: bytes, IV: bytes, sha: SHA256.SHA256Hash, input: BufferedReader, output: BufferedWriter) -> SHA256.SHA256Hash:
    data = input.read(AES.block_size)

    while data:
        if len(data) < AES.block_size:
            data = pad(data, AES.block_size)

        block = AES.new(Kc, AES.MODE_CBC, IV=IV).encrypt(data)
        sha.update(block)
        output.write(block)
        IV = block

        data = input.read(AES.block_size)

    return sha

def symDec(Kc: bytes, IV: bytes, sha: SHA256.SHA256Hash, signSize: int, input: BufferedReader, output: BufferedWriter) -> SHA256.SHA256Hash:
    start = input.tell()
    input.seek(0, os.SEEK_END)
    end = input.tell() - signSize
    input.seek(start, os.SEEK_SET)

    block = input.read(AES.block_size)

    while block:
        sha.update(block)
        data = AES.new(Kc, AES.MODE_CBC, IV=IV).decrypt(block)

        if (input.tell() == end):
            data = unpad(data, AES.block_size)
            block = None
        else:
            IV = block
            block = input.read(AES.block_size)

        output.write(data)

    return sha

def tryFetchKeys(input: BufferedReader, sha: SHA256.SHA256Hash, privKey: RSA.RsaKey, pubKeyData: bytes) -> bytes:
    targetKeyHash = SHA256.new(pubKeyData).digest()

    wrapKey = None

    # Try to match the keys as long as there are keys to read
    delimiter = input.read(1)
    sha.update(delimiter)
    while delimiter == b'\x00':
        keyHash = input.read(SHA256.digest_size)
        encKey = input.read(privKey.size_in_bytes())

        # Return the cipher if the keys match
        if (wrapKey == None) and (keyHash == targetKeyHash):
            wrapKey = PKCS1_OAEP.new(privKey).decrypt(encKey)

        delimiter = input.read(1)
        sha.update(keyHash + encKey + delimiter)
    
    return wrapKey, sha

def fetchFileData(keyPath: str) -> bytes:
    with open(keyPath, "rb") as keyFile:
        keyData = keyFile.read()
        if (keyData == None):
            raise IOError(f"Couldn't read the key file {keyPath}")
        return keyData
    return None

def unprotect(input: BufferedReader, output: BufferedWriter, privKeyPath: str, pubKeyPath: str, signKeyPath: str) -> int:
    # Create the sha object for the signature
    sha = SHA256.new()


    # Fetch KC, IV
    privKeyData = fetchFileData(privKeyPath)
    pubKeyData = fetchFileData(pubKeyPath)
    signKeyData = fetchFileData(signKeyPath)

    privKey = RSA.import_key(privKeyData)
    pubKey = RSA.import_key(pubKeyData)
    signKey = RSA.import_key(signKeyData)

    wrapKey, sha = tryFetchKeys(input, sha, privKey, pubKeyData)
    if (wrapKey == None):
        print("ERROR: Unable to find key in file")
        return 1
    
    kc = wrapKey[:AES.key_size[2]]
    iv = wrapKey[AES.key_size[2]:]

    hash = symDec(kc, iv, sha, privKey.size_in_bytes(), input, output)
    signature = input.read(privKey.size_in_bytes())

    try:
        pss.new(signKey).verify(hash, signature)
        return 0
    except:
        print("ERROR: Signature validation failed !")
        return 1



def protect(input: BufferedReader, output: BufferedWriter, signKeyPath: str, receiverPubKeyList: List) -> int:
    # Create the sha object for the signature
    sha = SHA256.new()
    
    # Create the AES Keys
    kc = get_random_bytes(AES.key_size[2])
    iv = get_random_bytes(AES.block_size)

    # Write key data
    try:
        for receiverPubKey in receiverPubKeyList:
            cipher = PKCS1_OAEP.new(RSA.import_key(receiverPubKey))
            wrapKey = cipher.encrypt(kc + iv)
            keySegment = b'\0' + SHA256.new(receiverPubKey).digest() + wrapKey
            sha.update(keySegment)
            output.write(keySegment)
    except Exception as e:
        print(f"ERROR: Unable to process the receiver list: {e}")
        return 1
    
    # Write cipher data
    output.write(b'\1')
    sha.update(b'\1')
    hash = symEnc(kc, iv, sha, input, output)

    # Write signature
    try:
        signKeyData = fetchFileData(signKeyPath)
        signature = pss.new(RSA.import_key(signKeyData)).sign(hash)
        output.write(signature)
    except Exception as e:
        print(f"ERROR: Unable to sign file: {e}")
        return 1

    return 0

def printUsage():
    print("Usage:")
    print(f"{sys.argv[0]} -e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]")
    print(f"{sys.argv[0]} -d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>")

# Entry point
def main(argv: List[str]) -> int:
    # Check the number of args
    if len(sys.argv) < 6:
        printUsage()
        return 1
    
    mode = sys.argv[1]

    # Check for the persence of the required modes
    if mode != "-e" and mode != "-d":
        printUsage()
        return 1

    # Define the input and output files
    input = None
    output = None

    # Try to open the input file. Returns 1 if unsucessful.
    try:
        input = open(sys.argv[2], "rb")
    except:
        print("ERROR: Couldn't open input file")
        return 1

    # Try to open the output file. Returns 1 if unsucessful.
    try:
        output = open(sys.argv[3], "wb")
    except:
        input.close()
        print("ERROR: Couldn't open output file")
        return 1
    
    status = 0
    if (mode == "-e"):
        keys = []
        for keyPath in sys.argv[5:]:
            with open(keyPath, "rb") as key:
                keys.append(key.read())

        # Then we call the main protect method
        status = protect(input, output, sys.argv[4], keys)
    elif (mode == "-d"):
        status = unprotect(input, output, sys.argv[4], sys.argv[5], sys.argv[6])
    
    input.close()
    output.close()

    return status

# Map the main function
if __name__ == "__main__":
    sys.exit(main(sys.argv))