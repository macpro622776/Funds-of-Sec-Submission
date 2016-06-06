import os
from Crypto.PublicKey import RSA
from Crypto.Signature import PKCS1_v1_5
from Crypto.Cipher import PKCS1_v1_5 as PKCS1_cipher
from Crypto.Hash import SHA256

def sign_file(f):
    # TODO: For Part 2, you'll use public key crypto here
    # The existing scheme just ensures the updates start with the line 'Caesar'
    # This is naive -- replace it with something better!
    
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
    hashed_m = SHA256.new(f)
    
    # Encrypt message using public key
    cipher = PKCS1_cipher.new(public_key)
    ciphertext = cipher.encrypt(f+hashed_m.digest())
    
    # Export private key to be prefixed to ciphertext
    export_prkey = key.exportKey('PEM')
    
    # Sign message using private key
    prkey = RSA.importKey(export_prkey)
    signer = PKCS1_v1_5.new(prkey)
    signature = signer.sign(hashed_m)
    
    # Return private key and ciphertext, as well as signature separately
    return export_prkey + b"\n" + ciphertext, signature

if __name__ == "__main__":
    fn = input("Which file in pastebot.net should be signed? ")
    if not os.path.exists(os.path.join("pastebot.net", fn)):
        print("The given file doesn't exist on pastebot.net")
        os.exit(1)
    f = open(os.path.join("pastebot.net", fn), "rb").read()
    signed_f, signature = sign_file(f)
    # Write signature file
    sig_fn = os.path.join("pastebot.net", "signature")
    sig_out = open(sig_fn, "wb")
    sig_out.write(signature)
    sig_out.close()
    # Write encrypted message
    signed_fn = os.path.join("pastebot.net", fn + ".signed")
    out = open(signed_fn, "wb")
    out.write(signed_f)
    out.close()
    print("Signed file written to", signed_fn)
