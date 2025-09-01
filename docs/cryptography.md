# Cryptography on Cordyceps
Our implementation of the cryptographic functions for **Cordyceps** is designed to strike a balance between a maintainable codebase and robust, standardized security. We've chosen a hybrid approach that uses both symmetric and asymmetric cryptography to protect our data.

At a high level, the process begins with a primary layer of symmetric encryption. We generate a random AES-GCM 256-bit key and a nonce, which are then used to encrypt the plaintext file content. The [aes_gcm](https://crates.io/crates/aes_gcm) module automatically appends an authentication tag to the resulting ciphertext due to the nature of [Galois/Counter Mode (GCM)](https://en.wikipedia.org/wiki/Galois/Counter_Mode). It achieves this using a block cipher in Counter (CTR) mode, which eliminates the need for padding and makes the output size predictable. This is a crucial step for integrity and authenticity, ensuring the data hasn't been tampered with.

The next challenge is securely transmitting the symmetric AES key. Simply embedding it in the file would make the entire system vulnerable to anyone who finds it. This is where our second layer of encryption comes in.

To solve this confidentiality problem, we leverage an [Elliptic Curve Integrated Encryption Scheme (ECIES)](https://medium.com/asecuritysite-when-bob-met-alice/elliptic-curve-integrated-encryption-scheme-ecies-encrypting-using-elliptic-curves-dc8d0b87eaa)-like approach. This algorithm works as follows:

1. A 256-bit [Curve25519](https://en.wikipedia.org/wiki/Curve25519) main public key is provided to our function. This is a static public key belonging to the intended recipient.
2. We generate a new, one-time ephemeral 256-bit key pair for each encryption operation.
3. Using our ephemeral private key and the recipient's main public key, we perform an [Elliptic Curve Diffie-Hellman (ECDH)](https://en.wikipedia.org/wiki/Elliptic-curve_Diffie%E2%80%93Hellman) key exchange to derive a unique shared secret.
4. This shared secret is then used as input to a Key Derivation Function (KDF). The KDF generates a new, unique AES-GCM key specifically for encrypting our file's symmetric AES key.

This two-step process means that in order to decrypt the file, the recipient must possess the corresponding main private key. With this private key and the ephemeral public key from the file's header, they can recreate the same shared secret. This allows them to decrypt the encapsulated AES key, which is then used to decrypt the main file content.

The final encrypted file is a structured package. Its header contains all the necessary components for secure decryption: the ephemeral public key, the encrypted AES key and its GCM authentication tag, and the nonces used for both the key encapsulation and file content encryption. This modular design ensures that all the information required for decryption is available in one file, while the main private key remains securely offline.

The next sections show graphically how both encryption and decryption processes work.


## Encryption
```mermaid
graph LR
    subgraph Stage 1: File Content Encryption
        A[Start: Read plaintext file] --> B{Generate random AES key & nonce}
        B --> C{Encrypt plaintext with AES key}
        C --> D[Result: File ciphertext + GCM tag]
    end

    subgraph Stage 2: Key Encapsulation
        E[Input: Recipient main public key] --> F{Generate ephemeral key pair}
        F --> G{ECDH: Derive shared secret}
        E --> G
        G --> H{HKDF: Derive new AES key for encapsulation}
        H --> I{Generate random AES nonce for encapsulation}
        I --> J{Encrypt File AES key with new key and nonce}
        J --> K[Result: Encapsulated AES key + GCM tag]
    end

    subgraph Stage 3: File Assembly
        L(Final assembly)
        M[Magic bytes] --> L
        N[File format version] --> L
        F -- Ephemeral public key --> L
        K --> L
        I -- Encapsulation nonce --> L
        B -- File content nonce --> L
        B -- File content AES key --> J
        L --> O[Deliverable: File header]

        O --> P[Write to encrypted .zombie file]
        D --> P
    end
```


## Decryption
```mermaid
graph LR
    subgraph Stage 1: File Parsing and Key Decapsulation
        A[Start: Read encrypted .zombie file] --> B{Read header & file content}
        B --> C[Result: Header elements] & D[Result: Encrypted file content]

        subgraph Key Decapsulation
            direction TB
            E[Input: Main private key] --> F{ECDH: Derive shared secret}
            C -- Ephemeral public key --> F
            F --> G{HKDF: Derive encapsulation AES Key}
            G --> H{Decrypt encapsulated file key}
            C -- Encapsulated AES key + GCM tag --> H
            C -- Encapsulation nonce --> H
            H --> I[Result: File AES Key]
        end
    end

    subgraph Stage 2: Content Decryption
        I --> J{Decrypt file Content with AES key}
        C -- File content nonce --> J
        D --> J
        J --> K[Result: File plaintext]
    end

    subgraph Stage 3: File Assembly
        K --> L{Write plaintext to new file}
        L --> M[End: Decrypted plaintext file]
    end
```
