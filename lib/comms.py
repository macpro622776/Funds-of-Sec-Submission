import struct
from Crypto.Cipher import AES
from Crypto.Hash import HMAC, SHA512
from Crypto import Random
from Crypto.Random import get_random_bytes
from dh import create_dh_key, calculate_dh_secret, get_prime
from lib.crypto_utils import ANSI_X923_pad, ANSI_X923_unpad
from datetime import datetime, time

class StealthConn(object):
    def __init__(self, conn, client=False, server=False, verbose=False):
        self.conn = conn
        self.cipher = None
        self.client = client
        self.server = server
        self.verbose = verbose
        # This shared hash is just a placeholder for a real hash to be assigned to the variable; it is never used directly
        self.shared_hash = b'Sixteen byte key'
        # Set AES mode
        self.aes_mode = AES.MODE_CBC
        self.initiate_session()

    def initiate_session(self):
        # Perform the initial connection handshake for agreeing on a shared secret

        ### TODO: Your code here!
        # This can be broken into code run just on the server or just on the client
        if self.server or self.client:
            my_public_key, my_private_key = create_dh_key()
            # Send them our public key
            padded_m = ANSI_X923_pad(str(my_public_key).encode("ascii"), AES.block_size)
            self.send(padded_m)
            # Receive their public key
            their_public_key = self.recv()
            their_public_unpad = ANSI_X923_unpad(their_public_key, AES.block_size)
            their_public_int = int(their_public_unpad)
            # Obtain our shared secret
            self.shared_hash = calculate_dh_secret(their_public_int, my_private_key)
            print("Shared hash: {}".format(self.shared_hash))

        # Initialise AES cipher for initiating session
        iv = Random.new().read(AES.block_size)
        self.cipher = AES.new(self.shared_hash[:32], self.aes_mode, iv)
        
        print("This session will last until the end of this hour.")

    def send(self, data):
        # Generate session key from current hour, then hash it
        session_key = datetime.now().time().hour
        h_session_key = SHA512.new(bytes(str(session_key), "ascii")).hexdigest().encode("ascii")
        
        # Reinitalise IV and AES cipher for encryption
        iv = Random.new().read(AES.block_size)
        self.cipher = AES.new(self.shared_hash[:32], self.aes_mode, iv)
        
        if self.cipher:
            # Calculate HMAC prior to encrypting message and save hexdigest for later transmission
            hmac_send = bytes(HMAC.new(data).hexdigest(), "ascii")
            
            # Encrypt hashed session key, HMAC and padded message, then prefix with the IV
            encrypted_data = iv + self.cipher.encrypt(h_session_key + hmac_send + ANSI_X923_pad(data, AES.block_size))
            
            if self.verbose:
                print("Original data: {}".format(data))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Sending packet of length {}".format(len(encrypted_data)))
        else:
            encrypted_data = data

        # Encode the data's length into an unsigned two byte int ('H')
        pkt_len = struct.pack('H', len(encrypted_data))
        self.conn.sendall(pkt_len)
        self.conn.sendall(encrypted_data)

    def recv(self):
        # Generate session key from current hour, then hash it
        session_key = datetime.now().time().hour
        h_session_key = SHA512.new(bytes(str(session_key), "ascii")).hexdigest().encode("ascii")
        
        # Decode the data's length from an unsigned two byte int ('H')
        pkt_len_packed = self.conn.recv(struct.calcsize('H'))
        unpacked_contents = struct.unpack('H', pkt_len_packed)
        pkt_len = unpacked_contents[0]

        encrypted_data = self.conn.recv(pkt_len)
        if self.cipher:
            # Decrypt received data and remove IV, then unpad data
            decrypted_data = ANSI_X923_unpad(self.cipher.decrypt(encrypted_data)[AES.block_size:], AES.block_size)
            
            # Separate hashed session key and HMAC from message
            data = decrypted_data[160:]
            hmac_received = decrypted_data[128:160]
            h_session_key_received = decrypted_data[:128]
            
            # Calculate HMAC of received message
            hmac_received_m = bytes(HMAC.new(data).hexdigest(), "ascii")
            
            # Check for matching HMACs to confirm message integrity and close connection if they do not match
            if hmac_received != hmac_received_m:
                self.closeWarning("HMAC does not match! Cannot guarantee message integrity!")
            
            # Check for matching session keys and close connection if they do not match
            if h_session_key != h_session_key_received:
                self.closeWarning("Session keys do not match.")

            if self.verbose:
                print("Receiving packet of length {}".format(pkt_len))
                print("Encrypted data: {}".format(repr(encrypted_data)))
                print("Original data: {}".format(data))
        else:
            data = encrypted_data

        return data
        
    def closeWarning(self, message):
        print(message)
        self.close()

    def close(self):
        print("Terminating session...")
        self.conn.close()