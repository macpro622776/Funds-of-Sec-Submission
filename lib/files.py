import os
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.Hash import SHA256
from Crypto import Random

# Instead of storing files on disk,
# we'll save them in memory for simplicity
filestore = {}
# Valuable data to be sent to the botmaster
valuables = []

###

def save_valuable(data):
    valuables.append(data)

def encrypt_for_master(data):
    # Encrypt the file so it can only be read by the bot master
    
    # Generate key pairs
    key = RSA.generate(2048)
    
    # Export public key to file
    export_pukey = key.publickey().exportKey('PEM')
    publickey_file = open(os.path.join("pastebot.net", "publickey"), "wb")
    publickey_file.write(export_pukey)
    publickey_file.close()
    
    # Create RSA object from public key
    publickey_file = open(os.path.join("pastebot.net", "publickey"), "rb").read()
    public_key = RSA.importKey(publickey_file)
    
    # Hash message
    hashed_m = SHA256.new(data)
    
    # Encrypt message using public key
    cipher = PKCS1_cipher.new(public_key)
    ciphertext = cipher.encrypt(data+hashed_m.digest())
    
    # Export private key to be prefixed to ciphertext
    export_prkey = key.exportKey('PEM')
    
    # Sign message using private key
    prkey = RSA.importKey(export_prkey)
    signer = PKCS1_v1_5.new(prkey)
    signature = signer.sign(hashed_m)
    
    # Return private key and ciphertext, as well as signature separately
    return export_prkey + b"\n" + ciphertext, signature

def upload_valuables_to_pastebot(fn):
    # Encrypt the valuables so only the bot master can read them
    valuable_data = "\n".join(valuables)
    valuable_data = bytes(valuable_data, "ascii")
    encrypted_master, signature = encrypt_for_master(valuable_data)
    
    # Write signature file - publish in public directory
    sig_fn = os.path.join("pastebot.net", "signature")
    sig_out = open(sig_fn, "wb")
    sig_out.write(signature)
    sig_out.close()

    # "Upload" it to pastebot (i.e. save in pastebot folder)
    f = open(os.path.join("pastebot.net", fn), "wb")
    f.write(encrypted_master)
    f.close()

    print("Saved valuables to pastebot.net/%s for the botnet master" % fn)

###

def verify_file(f, signature):
    # Verify the file was sent by the bot master
    # TODO: For Part 2, you'll use public key crypto here
    # Naive verification by ensuring the first line has the "passkey"
    
    # Split message up by line breaks into an array
    split_f = f.split(b"\n")
    
    # Check for a private key
    if len(split_f) < 27:
        return False
    
    # Decrypt the message using the private key
    message, dsize = decrypt_message(split_f)
    
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
        return verifier.verify(hashed_m, signature)

def process_file(fn, f, signature):
    if verify_file(f, signature):
        # If it was, store it unmodified
        # (so it can be sent to other bots)
        # Decrypt and run the file
        filestore[fn] = f
        print("Stored the received file as %s" % fn)
        run_file(filestore[fn], signature)
    else:
        print("The file has not been signed by the botnet master")

def download_from_pastebot(fn):
    # "Download" the file from pastebot.net
    # (i.e. pretend we are and grab it from disk)
    # Open the file as bytes and load into memory
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        return
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    # Open "signature" in the "pastebot.net" directory
    signature = open(os.path.join("pastebot.net", "signature"), "rb").read()
    process_file(fn, f, signature)

def p2p_download_file(sconn):
    # Download the file from the other bot
    fn = str(sconn.recv(), "ascii")
    f = sconn.recv()
    # Open "signature" in the "pastebot.net" directory
    signature = open(os.path.join("pastebot.net", "signature"), "rb").read()
    print("Receiving %s via P2P" % fn)
    process_file(fn, f, signature)

###

def p2p_upload_file(sconn, fn):
    # Grab the file and upload it to the other bot
    # You don't need to encrypt it only files signed
    # by the botnet master should be accepted
    # (and your bot shouldn't be able to sign like that!)
    if fn not in filestore:
        print("That file doesn't exist in the botnet's filestore")
        return
    print("Sending %s via P2P" % fn)
    sconn.send(bytes(fn, "ascii"))
    sconn.send(filestore[fn])

def run_file(f, signature):
    # If the file can be run,
    # run the commands
    
    # Split message up by line breaks into an array
    split_f = f.split(b"\n")
    
    # Decrypt the message using the private key
    message, dsize = decrypt_message(split_f)
    
    # Print message
    print(str(message[:-dsize], "ascii"))

def decrypt_message(split_f):
    # Form private key from first 27 lines of array
    key = b""
    for i in range(0,27):
        key += split_f[i] + b"\n"
        
    # Form message by concatenating lines
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
    
    # Return message and digest size
    return message, dsize