import os
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.Hash import SHA256
from Crypto import Random

def decrypt_valuables(f, signature):
    # TODO: For Part 2, you'll need to decrypt the contents of this file
    # The existing scheme uploads in plaintext
    # As such, we just convert it back to ASCII and print it out
    
    # Split message up by line breaks into an array
    split_f = f.split(b"\n")
    
    # Check for a private key
    if len(split_f) < 27:
        raise ValueError("No private key found - is this the correct file?")
    
    # Form private key from first 27 lines of array
    key = b""
    for i in range(0,27):
        key += split_f[i] + b"\n"
    
    # Form message from remaining lines of array
    message = b""
    if len(split_f)-1 == 27:
        message = split_f[len(split_f)-1]
    else:
        for i in range(27,len(split_f)-1):
            message += split_f[i] + b"\n"
        message += split_f[len(split_f)-1]
    
    # Create an RSA object using the private key and use it to decrypt the message
    key = RSA.importKey(key)
    dsize = SHA256.digest_size
    sentinel = Random.new().read(15+dsize)
    cipher = PKCS1_cipher.new(key)
    message = cipher.decrypt(message, sentinel)
    
    # Verify encryption
    digest = SHA256.new(message[:-dsize]).digest()
    if digest == message[-dsize:]:
        # Remove digest from message
        message = message[:-dsize]
        
        # Hash message for verification
        hashed_m = SHA256.new(message)
        
        # Verify signature using the public key
        pukey = RSA.importKey(open(os.path.join("pastebot.net", "publickey"), "rb").read())
        verifier = PKCS1_v1_5.new(pukey)
        if verifier.verify(hashed_m, signature):
            # Print the message
            print(str(message, "ascii"))
        else:
            print("Encryption was correct")
            print("Signature NOT verified")
    else:
        print("Encryption was incorrect")


if __name__ == "__main__":
    fn = input("Which file in pastebot.net does the botnet master want to view? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    # Open "signature" in the "pastebot.net" directory
    signature = open(os.path.join("pastebot.net", "signature"), "rb").read()
    decrypt_valuables(f, signature)
