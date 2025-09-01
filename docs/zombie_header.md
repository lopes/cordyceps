# .zombie File Header Format
This document details the binary structure of the `.zombie` file header. A consistent header format is crucial as it contains all the necessary cryptographic metadata required for successful decryption. This design allows the encrypted payload to be self-contained, meaning no out-of-band information (other than the main private key) is needed for recovery.

The header has a fixed size of **109 bytes**.

## Header Layout
The following diagram illustrates the structure of the `.zombie` header:

```
    0               1                   2                   3
    0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8 9 0 1 2 3 4 5 6 7 8
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                      Magic ("CORD")                     |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |    Version    |                                         |
   +-+-+-+-+-+-+-+-+                                         +
   |                                                         |
   |                  Ephemeral Public Key                   |
   |                        (32 bytes)                       |
   |                                                         |
   |                                                         |
   |                                                         |
   |                                                         |
   |                                                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                         |
   |                                                         |
   |                  Encrypted File AES Key                 |
   |                (Ciphertext + 16-byte Tag)               |
   |                        (48 bytes)                       |
   |                                                         |
   |                                                         |
   |                                                         |
   |                                                         |
   |                                                         |
   |                                                         |
   |                                                         |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                         |
   |                    Key Encapsulation                    |
   |                      AES-GCM Nonce                      |
   |                        (12 bytes)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                         |
   |                       File Content                      |
   |                      AES-GCM Nonce                      |
   |                        (12 bytes)                       |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
   |                                                         |
   |              Encrypted File Content (Payload)           |
   |                            ...                          |
   +-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+-+
```

## Field Descriptions
- **Magic (4 bytes):** The ASCII characters `CORD`. This sequence serves as a magic number to quickly identify the file as a Cordyceps-encrypted file and verify its integrity.

- **Version (1 byte):** An 8-bit unsigned integer representing the file format version. The current version is `1`. This allows for future updates to the format while maintaining backward compatibility.

- **Ephemeral Public Key (32 bytes):** The 32-byte Curve25519 public key generated for this specific encryption session. It is required by the recipient to perform the Elliptic-Curve Diffie-Hellman (ECDH) key exchange and derive the shared secret needed to decrypt the file's AES key.

- **Encrypted File AES Key (48 bytes):** This field contains the 32-byte AES-256-GCM key (which was used to encrypt the actual file content) after it has been encrypted using the ECIES-like scheme. The 16-byte GCM authentication tag is appended to the ciphertext, resulting in a total size of 48 bytes.

- **Key Encapsulation AES-GCM Nonce (12 bytes):** The 96-bit (12-byte) nonce used for the AES-GCM encryption of the file's symmetric AES key. It ensures that the key encapsulation is secure and unique.

- **File Content AES-GCM Nonce (12 bytes):** The 96-bit (12-byte) nonce used for the AES-GCM encryption of the main file content. It ensures the file content encryption is secure and unique.
