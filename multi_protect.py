#!/usr/bin/python3

# Proteger input_file
# $ python multi_protect.py -e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]
# retourne 0 si OK, 1 sinon

# Deproteger input_file 
# $ python multi_protect.py -d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem> 
# retourne 0 si OK, 1 sinon

import sys
from typing import List
from io import BufferedWriter
from Crypto.PublicKey import RSA
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Signature import pss
from Crypto.Util.Padding import pad, unpad
from Crypto.Random import get_random_bytes

# Verify that our key is present in the file
def tryFetchKeys(input: bytes, privKey: RSA.RsaKey, pubKeyData: bytes) -> bytes:
    targetKeyHash = SHA256.new(pubKeyData).digest()

    wrapKey = None

    # Try to match the keys as long as there are keys to read
    keySectionLen = 1 + SHA256.digest_size + privKey.size_in_bytes()
    for i in range(0, len(input), keySectionLen):
        keySection = input[i:i + keySectionLen]

        if keySection[0] == 0:
            keyHash = keySection[1: 1 + SHA256.digest_size]
            encKey = keySection[1 + SHA256.digest_size:1 + SHA256.digest_size + privKey.size_in_bytes()]

            # Return the cipher if the keys match
            if (wrapKey == None) and (keyHash == targetKeyHash):
                wrapKey = PKCS1_OAEP.new(privKey).decrypt(encKey)
        elif keySection[0] == 1:
            return wrapKey, i + 1
        else:
            raise IOError("File format exception")

# Read a file to a buffer and exit
def fetchFileData(keyPath: str) -> bytes:
    with open(keyPath, "rb") as keyFile:
        keyData = keyFile.read()
        if (keyData == None):
            raise IOError(f"Couldn't read file {keyPath}")
        return keyData
    return None

def unprotect(input: bytes, output: BufferedWriter, privKeyPath: str, pubKeyPath: str, signKeyPath: str) -> int:
    privKey = None
    signKey = None
    
    try:
        # Load the required keys from disk
        privKeyData = fetchFileData(privKeyPath)
        pubKeyData = fetchFileData(pubKeyPath)
        signKeyData = fetchFileData(signKeyPath)

        privKey = RSA.import_key(privKeyData)
        signKey = RSA.import_key(signKeyData)
    except Exception as e:
        print(f"ERROR: Unable to load keys : {e}")
        return 1

    # Separate out the signature from the signed filedata
    filedata = input[:-signKey.size_in_bytes()]
    hash = SHA256.new(filedata)
    signature = input[-signKey.size_in_bytes():]

    try:
        # Verity the file signature
        pss.new(signKey).verify(hash, signature)
    except Exception as e:
        print(f"ERROR: Signature validation failed : {e}")
        return 1

    wrapKey = None
    try:
        # Verify that out key is in the input file
        wrapKey, offset = tryFetchKeys(filedata, privKey, pubKeyData)
    except Exception as e:
        print(f"ERROR: Unable to fetch recipient keys: {e}")
        return 1
    
    if (wrapKey == None):
        print("ERROR: Recipient key abscent from the provided file")
        return 1
    
    # Fetch KC, IV
    kc = wrapKey[:AES.key_size[2]]
    iv = wrapKey[AES.key_size[2]:]

    # Encrypt the file data
    outputData = unpad(AES.new(kc, AES.MODE_CBC, iv=iv).decrypt(filedata[offset:]), AES.block_size)

    # Then write it to the output file
    output.write(outputData)

    return 0

def protect(input: bytes, output: BufferedWriter, signKeyPath: str, receiverPubKeyList: List) -> int:
    # Create the AES Keys
    kc = get_random_bytes(AES.key_size[2])
    iv = get_random_bytes(AES.block_size)

    # Create the output data buffer
    outputData = b''

    # Write key data
    try:
        for receiverPubKey in receiverPubKeyList:
            cipher = PKCS1_OAEP.new(RSA.import_key(receiverPubKey))
            wrapKey = cipher.encrypt(kc + iv)
            keySegment = b'\0' + SHA256.new(receiverPubKey).digest() + wrapKey
            outputData += keySegment
    except Exception as e:
        print(f"ERROR: Unable to process the receiver list: {e}")
        return 1


    # Write cipher data
    outputData += b'\1' + AES.new(kc, AES.MODE_CBC, iv=iv).encrypt(pad(input, AES.block_size))

    # Compute the file data hash
    hash = SHA256.new(outputData)

    # Write signature
    try:
        signKeyData = fetchFileData(signKeyPath)
        signature = pss.new(RSA.import_key(signKeyData)).sign(hash)
        outputData += signature
    except Exception as e:
        print(f"ERROR: Unable to sign file: {e}")
        return 1
    
    # Then write all data to file
    output.write(outputData)

    return 0

# Prints the usage of the program
def printUsage():
    print("Usage:")
    print(f"{sys.argv[0]} -e <input_file> <output_file> <my_sign_priv.pem> <my_ciph_pub.pem> [user1_ciph_pub.pem ... [userN_ciph_pub.pem]]")
    print(f"{sys.argv[0]} -d <input_file> <output_file> <my_priv_ciph.pem> <my_pub_ciph.pem> <sender_sign_pub.pem>")

# Entry point
def main(argv: List[str]) -> int:
    # Check the number of args
    if len(sys.argv) < 7:
        printUsage()
        return 1
    
    mode = sys.argv[1]

    # Check for the persence of the required modes
    if mode != "-e" and mode != "-d":
        printUsage()
        return 1

    # Define the inputData and output file
    inputData = None
    outputFile = None

    # Try to open the input file. Returns 1 if unsucessful.
    try:
        with open(sys.argv[2], "rb") as inputFile:
            inputData = inputFile.read()
    except:
        print("ERROR: Couldn't open input file")
        return 1

    # Try to open the output file. Returns 1 if unsucessful.
    try:
        outputFile = open(sys.argv[3], "wb")
    except:
        print("ERROR: Couldn't open output file")
        return 1
    
    status = 0
    if (mode == "-e"):
        # We first get the data from all the recipient keys including the one of the sender
        keys = []
        for keyPath in sys.argv[5:]:
            with open(keyPath, "rb") as key:
                keys.append(key.read())

        # Then we call the main protect method
        status = protect(inputData, outputFile, sys.argv[4], keys)
    elif (mode == "-d"):
        # For the decrypt mode we can directly call the method
        status = unprotect(inputData, outputFile, sys.argv[4], sys.argv[5], sys.argv[6])

    # Finally we close the output file
    outputFile.close()

    return status

# Map the main function
if __name__ == "__main__":
    sys.exit(main(sys.argv))