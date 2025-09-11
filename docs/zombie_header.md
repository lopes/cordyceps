# .zombie File Header Format
This document details the binary structure of the `.zombie` file header. A consistent header format is crucial as it contains all the necessary cryptographic metadata required for successful decryption. This design allows the encrypted payload to be self-contained, meaning no out-of-band information (other than the main private key) is needed for recovery.

The header has a fixed size of **109 bytes**.


## Header Layout
The following diagram illustrates the structure of the `.zombie` header:

```
    0               1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Magic ("CORD")                           | 0-3
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Version    |                                               | 4-7
   |                  Ephemeral Public Key                         | 8-11
   |                        (32 bytes)                             | 12-15
   |                                                               | 16-19
   |                                                               | 20-23
   |                                                               | 24-27
   |                                                               | 28-31
   |                                                               | 32-35
   |                                               |               | 36
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               | 37-40
   |                                                               | 41-44
   |                  Encrypted File AES Key                       | 45-48
   |                (Ciphertext + 16-byte Tag)                     | 49-52
   |                        (48 bytes)                             | 53-56
   |                                                               | 57-60
   |                                                               | 61-64
   |                                                               | 65-68
   |                                                               | 69-72
   |                                                               | 73-76
   |                                                               | 77-80
   |                                                               | 81-84
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               | 85-88
   |                    KEK Nonce                                  | 89-92
   |                   (12 bytes)                                  | 93-96
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                               | 97-100
   |                    DEK Nonce                                  | 101-104
   |                   (12 bytes)                                  | 105-108
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Field Descriptions
### Magic (4 bytes, offset 0-3)
The ASCII characters `CORD` stored as bytes `0x43 0x4F 0x52 0x44`. This sequence serves as a magic number to quickly identify the file as a Cordyceps-encrypted file and verify its integrity at the byte level.

### Version (1 byte, offset 4)
An 8-bit unsigned integer representing the file format version. The current version is `1` (0x01). This allows for future updates to the format while maintaining backward compatibility.

### Ephemeral Public Key (32 bytes, offset 5-36)
The 32-byte Curve25519 public key generated for this specific encryption session. This key is required by the recipient to perform the Elliptic-Curve Diffie-Hellman (ECDH) key exchange and derive the shared secret needed to decrypt the file's AES key. The key is stored in raw binary format as output by the Curve25519 key generation function.

### Encrypted File AES Key (48 bytes, offset 37-84)
This field contains the 32-byte AES-256-GCM key (which encrypts the actual file content) after it has been encrypted using AES-256-GCM with the derived shared secret. The structure is:
- **Ciphertext (32 bytes):** The encrypted file AES key
- **Authentication Tag (16 bytes):** The GCM authentication tag

The total field size is 48 bytes. The authentication tag **MUST** be verified before attempting to decrypt the ciphertext.

### KEK Nonce (12 bytes, offset 85-96)
The 96-bit (12-byte) nonce used for the AES-GCM encryption of the file's symmetric AES key (Key Encryption Key operation). This nonce **MUST** be unique for each encryption operation to maintain semantic security. It is generated using a cryptographically secure random number generator.

### DEK Nonce (12 bytes, offset 97-108)
The 96-bit (12-byte) nonce used for the AES-GCM encryption of the main file content (Data Encryption Key operation). This nonce **MUST** be unique for each encryption operation and **MUST** be different from the KEK nonce. It is generated using a cryptographically secure random number generator.


## Implementation Notes
### Parsing Algorithm
```
1. Read and verify magic bytes (must be "CORD")
2. Read version byte (must be 1 for current format)
3. Extract ephemeral public key (32 bytes)
4. Extract encrypted AES key with tag (48 bytes)
5. Extract KEK nonce (12 bytes)
6. Extract DEK nonce (12 bytes)
7. Validate total header size is exactly 109 bytes
```

### Security Requirements
- **Nonce Uniqueness**: Nonces MUST be generated using a CSPRNG and MUST never be reused
- **Tag Verification**: The authentication tag in the encrypted AES key field MUST be verified before decryption
- **Key Derivation**: The shared secret from ECDH MUST be processed through HKDF-SHA256 with appropriate salt and info parameters
- **Constant-Time Operations**: All cryptographic operations SHOULD use constant-time implementations to prevent timing attacks--another good reason to rely on tested frameworks

### Error Handling
Implementations **MUST** reject files with:
- Incorrect magic bytes
- Unsupported version numbers
- Headers shorter or longer than 109 bytes
- Invalid authentication tags

### Example Header (Hexadecimal)
```
43 4F 52 44 01 4A 2B 1C  8F E3 A4 B5 C6 D7 E8 F9  | CORDJ+..........
0A 1B 2C 3D 4E 5F 60 71  82 93 A4 B5 C6 D7 E8 F9  | ..,=E_`q........
0A 1B 2C 3D 4E 5F 60 71  82 93 A4 B5 C6 D7 E8 F9  | ..,=E_`q........
[... encrypted key and tag (48 bytes) ...]
12 34 56 78 9A BC DE F0  12 34 56 78              | .4Vx....4Vx
AB CD EF 01 23 45 67 89  AB CD EF 01              | ...#Eg.....
```


## Version History
- **Version 1:** Initial format specification with AES-256-GCM encryption and Curve25519 ECDH key exchange
