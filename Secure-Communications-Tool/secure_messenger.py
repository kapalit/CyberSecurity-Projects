#!/usr/bin/env python3
"""
Secure Communications Tool
End-to-end encrypted messaging system with RSA and AES encryption
"""

import os
import json
import hashlib
import argparse
from datetime import datetime
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from base64 import b64encode, b64decode
import logging

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger(__name__)


class SecureMessenger:
    """Handles encryption/decryption and secure message transmission"""
    
    def __init__(self, key_size=2048):
        self.key_size = key_size
        self.private_key = None
        self.public_key = None
        
    def generate_keys(self, output_dir='keys'):
        """Generate RSA key pair"""
        logger.info("Generating RSA key pair...")
        os.makedirs(output_dir, exist_ok=True)
        
        # Generate private key
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.key_size,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Save private key
        private_pem = self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption()
        )
        private_path = os.path.join(output_dir, 'private_key.pem')
        with open(private_path, 'wb') as f:
            f.write(private_pem)
        logger.info(f"Private key saved to {private_path}")
        
        # Save public key
        public_pem = self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
        public_path = os.path.join(output_dir, 'public_key.pem')
        with open(public_path, 'wb') as f:
            f.write(public_pem)
        logger.info(f"Public key saved to {public_path}")
        
        return private_path, public_path
    
    def load_private_key(self, path):
        """Load private key from file"""
        with open(path, 'rb') as f:
            self.private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        logger.info(f"Private key loaded from {path}")
    
    def load_public_key(self, path):
        """Load public key from file"""
        with open(path, 'rb') as f:
            self.public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        logger.info(f"Public key loaded from {path}")
    
    def encrypt_message(self, message, recipient_public_key_path):
        """
        Encrypt message using hybrid encryption:
        1. Generate random AES key
        2. Encrypt message with AES
        3. Encrypt AES key with RSA
        """
        logger.info("Encrypting message...")
        
        # Load recipient's public key
        with open(recipient_public_key_path, 'rb') as f:
            recipient_public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        # Generate random AES key and IV
        aes_key = os.urandom(32)  # 256-bit key
        iv = os.urandom(16)  # 128-bit IV
        
        # Encrypt message with AES
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        encryptor = cipher.encryptor()
        
        # Add padding for AES
        message_bytes = message.encode('utf-8')
        padding_length = 16 - (len(message_bytes) % 16)
        padded_message = message_bytes + bytes([padding_length] * padding_length)
        
        ciphertext = encryptor.update(padded_message) + encryptor.finalize()
        
        # Encrypt AES key with RSA
        encrypted_aes_key = recipient_public_key.encrypt(
            aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Package encrypted message
        encrypted_data = {
            'encrypted_aes_key': b64encode(encrypted_aes_key).decode('utf-8'),
            'iv': b64encode(iv).decode('utf-8'),
            'ciphertext': b64encode(ciphertext).decode('utf-8'),
            'timestamp': datetime.now().isoformat()
        }
        
        logger.info("Message encrypted successfully")
        return json.dumps(encrypted_data, indent=2)
    
    def decrypt_message(self, encrypted_json):
        """Decrypt message using private key"""
        logger.info("Decrypting message...")
        
        if not self.private_key:
            raise ValueError("Private key not loaded")
        
        encrypted_data = json.loads(encrypted_json)
        
        # Decrypt AES key with RSA
        encrypted_aes_key = b64decode(encrypted_data['encrypted_aes_key'])
        aes_key = self.private_key.decrypt(
            encrypted_aes_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        
        # Decrypt message with AES
        iv = b64decode(encrypted_data['iv'])
        ciphertext = b64decode(encrypted_data['ciphertext'])
        
        cipher = Cipher(
            algorithms.AES(aes_key),
            modes.CBC(iv),
            backend=default_backend()
        )
        decryptor = cipher.decryptor()
        padded_message = decryptor.update(ciphertext) + decryptor.finalize()
        
        # Remove padding
        padding_length = padded_message[-1]
        message = padded_message[:-padding_length].decode('utf-8')
        
        logger.info("Message decrypted successfully")
        return message
    
    def sign_message(self, message):
        """Create digital signature for message"""
        if not self.private_key:
            raise ValueError("Private key not loaded")
        
        logger.info("Creating digital signature...")
        signature = self.private_key.sign(
            message.encode('utf-8'),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        
        return b64encode(signature).decode('utf-8')
    
    def verify_signature(self, message, signature_b64, sender_public_key_path):
        """Verify digital signature"""
        logger.info("Verifying digital signature...")
        
        with open(sender_public_key_path, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        
        signature = b64decode(signature_b64)
        
        try:
            public_key.verify(
                signature,
                message.encode('utf-8'),
                padding.PSS(
                    mgf=padding.MGF1(hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            logger.info("Signature verified successfully")
            return True
        except Exception as e:
            logger.error(f"Signature verification failed: {e}")
            return False
    
    def hash_password(self, password):
        """Hash password using SHA-256"""
        salt = os.urandom(32)
        pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return b64encode(salt + pwd_hash).decode('utf-8')
    
    def verify_password(self, password, password_hash):
        """Verify password against hash"""
        decoded = b64decode(password_hash)
        salt = decoded[:32]
        pwd_hash = decoded[32:]
        
        computed_hash = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
        return pwd_hash == computed_hash


class SecureChannel:
    """Manages secure communication session"""
    
    def __init__(self, user_id, messenger):
        self.user_id = user_id
        self.messenger = messenger
        self.message_history = []
    
    def send_message(self, recipient_id, message, recipient_public_key):
        """Send encrypted message"""
        logger.info(f"Sending message from {self.user_id} to {recipient_id}...")
        
        encrypted = self.messenger.encrypt_message(message, recipient_public_key)
        signature = self.messenger.sign_message(message)
        
        message_envelope = {
            'sender': self.user_id,
            'recipient': recipient_id,
            'encrypted_message': json.loads(encrypted),
            'signature': signature,
            'timestamp': datetime.now().isoformat()
        }
        
        self.message_history.append(message_envelope)
        return json.dumps(message_envelope, indent=2)
    
    def receive_message(self, message_envelope_json, sender_public_key):
        """Receive and decrypt message"""
        message_envelope = json.loads(message_envelope_json)
        
        # Verify sender
        if message_envelope['recipient'] != self.user_id:
            raise ValueError("Message not intended for this user")
        
        # Decrypt message
        encrypted_json = json.dumps(message_envelope['encrypted_message'])
        message = self.messenger.decrypt_message(encrypted_json)
        
        # Verify signature
        is_valid = self.messenger.verify_signature(
            message,
            message_envelope['signature'],
            sender_public_key
        )
        
        logger.info(f"Received message from {message_envelope['sender']}")
        logger.info(f"Signature valid: {is_valid}")
        
        return {
            'message': message,
            'sender': message_envelope['sender'],
            'timestamp': message_envelope['timestamp'],
            'signature_valid': is_valid
        }
    
    def save_history(self, filename='message_history.json'):
        """Save message history to file"""
        with open(filename, 'w') as f:
            json.dump(self.message_history, f, indent=2)
        logger.info(f"Message history saved to {filename}")


def main():
    parser = argparse.ArgumentParser(description='Secure Communications Tool')
    parser.add_argument('--mode', choices=['keygen', 'encrypt', 'decrypt', 'sign', 'verify'], 
                        required=True, help='Operation mode')
    parser.add_argument('--message', help='Message to encrypt/sign')
    parser.add_argument('--encrypted-file', help='Encrypted message file')
    parser.add_argument('--private-key', default='keys/private_key.pem', help='Private key path')
    parser.add_argument('--public-key', default='keys/public_key.pem', help='Public key path')
    parser.add_argument('--recipient-key', help='Recipient public key path')
    parser.add_argument('--signature-file', help='Signature file')
    parser.add_argument('--output', help='Output file path')
    
    args = parser.parse_args()
    
    messenger = SecureMessenger()
    
    try:
        if args.mode == 'keygen':
            messenger.generate_keys()
            logger.info("Key generation complete")
        
        elif args.mode == 'encrypt':
            if not args.message or not args.recipient_key:
                raise ValueError("--message and --recipient-key required for encryption")
            
            encrypted = messenger.encrypt_message(args.message, args.recipient_key)
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(encrypted)
                logger.info(f"Encrypted message saved to {args.output}")
            else:
                print("\n" + "="*60)
                print("ENCRYPTED MESSAGE")
                print("="*60)
                print(encrypted)
        
        elif args.mode == 'decrypt':
            if not args.encrypted_file or not args.private_key:
                raise ValueError("--encrypted-file and --private-key required for decryption")
            
            messenger.load_private_key(args.private_key)
            
            with open(args.encrypted_file, 'r') as f:
                encrypted_json = f.read()
            
            message = messenger.decrypt_message(encrypted_json)
            
            print("\n" + "="*60)
            print("DECRYPTED MESSAGE")
            print("="*60)
            print(message)
        
        elif args.mode == 'sign':
            if not args.message or not args.private_key:
                raise ValueError("--message and --private-key required for signing")
            
            messenger.load_private_key(args.private_key)
            signature = messenger.sign_message(args.message)
            
            print("\n" + "="*60)
            print("DIGITAL SIGNATURE")
            print("="*60)
            print(signature)
            
            if args.output:
                with open(args.output, 'w') as f:
                    f.write(signature)
                logger.info(f"Signature saved to {args.output}")
        
        elif args.mode == 'verify':
            if not args.message or not args.signature_file or not args.public_key:
                raise ValueError("--message, --signature-file, and --public-key required for verification")
            
            with open(args.signature_file, 'r') as f:
                signature = f.read().strip()
            
            is_valid = messenger.verify_signature(args.message, signature, args.public_key)
            
            print("\n" + "="*60)
            print(f"SIGNATURE VALID: {is_valid}")
            print("="*60)
    
    except Exception as e:
        logger.error(f"Error: {e}")
        return 1
    
    return 0


if __name__ == '__main__':
    exit(main())
