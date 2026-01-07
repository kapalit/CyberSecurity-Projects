# Secure Communications Tool

A comprehensive end-to-end encrypted messaging system demonstrating modern cryptographic techniques including RSA encryption, AES encryption, and digital signatures.

## Features

- **Hybrid Encryption**: Combines RSA (asymmetric) and AES (symmetric) encryption
- **Digital Signatures**: Sign and verify message authenticity using RSA-PSS
- **Key Management**: Generate and manage RSA key pairs (2048-bit)
- **Message Encryption**: Encrypt messages using recipient's public key
- **Message Decryption**: Decrypt messages using private key
- **Signature Verification**: Verify message authenticity and non-repudiation
- **Password Hashing**: Secure password storage using PBKDF2
- **Message History**: Track encrypted communications
- **JSON Format**: Easy integration with other systems

## How It Works

### Hybrid Encryption System

1. **Key Generation**
   - Generate 2048-bit RSA key pair (public and private)
   - Public key shared with recipients
   - Private key kept secure

2. **Message Encryption**
   - Generate random 256-bit AES key
   - Encrypt message with AES-CBC
   - Encrypt AES key with recipient's RSA public key
   - Send encrypted message and key to recipient

3. **Message Decryption**
   - Decrypt AES key using private RSA key
   - Use decrypted AES key to decrypt message
   - Verify message integrity

4. **Digital Signatures**
   - Sign message using private key (RSA-PSS)
   - Recipient verifies signature with sender's public key
   - Ensures authenticity and non-repudiation

## Installation

### Step 1: Install Python 3.11
```powershell
winget install Python.Python.3.11
```

### Step 2: Navigate to project directory
```powershell
cd "c:\Users\[YourUsername]\source\repos\Cybersecurity project\Secure-Communications-Tool"
```

### Step 3: Install dependencies
```powershell
&"C:\Users\[YourUsername]\AppData\Local\Programs\Python\Python311\python.exe" -m pip install -r requirements.txt
```

## Usage

### Generate Key Pair

```powershell
python secure_messenger.py --mode keygen
```

Creates `keys/private_key.pem` and `keys/public_key.pem`

### Encrypt a Message

```powershell
python secure_messenger.py --mode encrypt --message "Hello, World!" --recipient-key keys/public_key.pem --output encrypted.json
```

### Decrypt a Message

```powershell
python secure_messenger.py --mode decrypt --encrypted-file encrypted.json --private-key keys/private_key.pem
```

### Sign a Message

```powershell
python secure_messenger.py --mode sign --message "Important message" --private-key keys/private_key.pem --output signature.txt
```

### Verify a Signature

```powershell
python secure_messenger.py --mode verify --message "Important message" --signature-file signature.txt --public-key keys/public_key.pem
```

## Command-Line Arguments

- `--mode`: Operation mode (keygen, encrypt, decrypt, sign, verify)
- `--message`: Message to encrypt/sign
- `--encrypted-file`: Path to encrypted message file
- `--private-key`: Path to private key (default: keys/private_key.pem)
- `--public-key`: Path to public key (default: keys/public_key.pem)
- `--recipient-key`: Path to recipient's public key
- `--signature-file`: Path to signature file
- `--output`: Output file path

## Security Features

### RSA Encryption
- 2048-bit key size
- OAEP padding with SHA-256
- Secure key generation

### AES Encryption
- 256-bit keys (AES-256)
- CBC mode with random IV
- PKCS7 padding

### Digital Signatures
- RSA-PSS padding
- SHA-256 hashing
- Maximum salt length

### Password Security
- PBKDF2 hashing with SHA-256
- 32-byte random salt
- 100,000 iterations

## Workflow Example

### User A wants to send a secure message to User B

1. **Setup**
   ```powershell
   # User A generates keys
   python secure_messenger.py --mode keygen
   
   # User B generates keys
   python secure_messenger.py --mode keygen
   
   # Exchange public keys
   ```

2. **Send Message from A to B**
   ```powershell
   python secure_messenger.py --mode encrypt \
     --message "Secret information" \
     --recipient-key user_b_public_key.pem \
     --output message.json
   ```

3. **Receive and Decrypt at B**
   ```powershell
   python secure_messenger.py --mode decrypt \
     --encrypted-file message.json \
     --private-key user_b_private_key.pem
   ```

4. **Sign for Authentication**
   ```powershell
   python secure_messenger.py --mode sign \
     --message "Message content" \
     --private-key user_a_private_key.pem \
     --output signature.txt
   ```

5. **Verify Authenticity**
   ```powershell
   python secure_messenger.py --mode verify \
     --message "Message content" \
     --signature-file signature.txt \
     --public-key user_a_public_key.pem
   ```

## Encryption Standards

### RSA (Asymmetric)
- Algorithm: RSA-2048
- Padding: OAEP (Optimal Asymmetric Encryption Padding)
- Hash: SHA-256
- Use: Key encryption

### AES (Symmetric)
- Algorithm: AES-256-CBC
- Key Size: 256 bits
- Block Size: 128 bits
- IV: 128-bit random
- Use: Message encryption

### Signing
- Algorithm: RSA-PSS
- Hash: SHA-256
- Salt: Maximum length
- Use: Authentication and non-repudiation

## Encrypted Message Format

```json
{
  "encrypted_aes_key": "base64_encoded_rsa_encrypted_key",
  "iv": "base64_encoded_iv",
  "ciphertext": "base64_encoded_aes_encrypted_message",
  "timestamp": "2026-01-06T22:00:00.000000"
}
```

## Best Practices

1. **Key Storage**
   - Keep private keys secure (file permissions, encryption)
   - Store in secure locations
   - Use hardware security modules for production

2. **Key Distribution**
   - Exchange public keys through secure channels
   - Verify key fingerprints
   - Use key servers for large deployments

3. **Message Handling**
   - Always verify signatures
   - Check timestamps for replay attacks
   - Implement key rotation

4. **Password Management**
   - Use strong passwords
   - Hash with salt
   - Never store plaintext passwords

## Security Considerations

- This tool is for educational purposes
- Use established libraries for production systems
- Keep cryptography library updated
- Implement proper key management
- Follow security best practices

## Common Use Cases

- Secure email communication
- Confidential document transfer
- Authentication systems
- Digital signatures
- API security
- Secure configuration storage

## Troubleshooting

### Key not found
Make sure keys directory exists and paths are correct:
```powershell
ls keys/
```

### Decryption fails
- Verify using the correct private key
- Ensure encrypted file is valid JSON
- Check file encoding (UTF-8)

### Signature verification failed
- Verify using sender's public key
- Check message hasn't been modified
- Ensure signature file is correct

### Import errors
Install dependencies:
```powershell
python -m pip install -r requirements.txt
```

## References

- [NIST FIPS 186-4: DSS](https://nvlpubs.nist.gov/nistpubs/FIPS/NIST.FIPS.186-4.pdf)
- [RFC 3394: AES Key Wrap Algorithm](https://tools.ietf.org/html/rfc3394)
- [RFC 8017: PKCS #1: RSA](https://tools.ietf.org/html/rfc8017)

## Disclaimer

This tool is for educational purposes to demonstrate cryptographic concepts. For production systems, use established libraries and follow industry standards. Always implement proper key management and security practices.

## Author

Created for cybersecurity portfolio
