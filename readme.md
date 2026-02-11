# Super Simple Password Manager (SSPM)

## Overview

**SSPM** is a minimalist CLI-based password manager focused on strong security and extreme simplicity. It leverages modern cryptographic standards to ensure your data remains private, even if your local files are compromised.

---

## Features

- **Bank-Grade Security:** Authenticated encryption to guarantee both data integrity and confidentiality.
- **Folder Hierarchy:** Organize your passwords using logical paths (e.g., work/email).
- **Clipboard Integration:** Copy passwords directly to your clipboard without exposing them on your screen.

---

## Tech Stack and Security

- **Key Derivation Function (KDF):** Uses **Argon2id** (the winner of the Password Hashing Competition) to derive cryptographic keys from your master password, making it resilient against brute-force and GPU-based attacks.
- **Encryption:** **AES-256-GCM** (Galois/Counter Mode). Every password is encrypted with a unique 12-byte random nonce.
- **Integrity:** Uses **Authenticated Encryption (AEAD)** to ensure that your password database hasn't been tampered with.

---

## Installation

**Using Nix (Recommended)**

```bash
nix develop
# or run it directly
nix shell
```

**Using pip**

- Create a virtual enviroment.

```bash
python -m venv .venv
```

- Enable virtual enviroment.

```bash
# on unix
source .venv/bin/activate

# on windows
.venv\Scripts\activate.bat
```

- Install dependencies

```bash
pip install -r requirements.txt
```

---

## Usage Guide

1. Initialization

Set up your master password and Initialize the vault:

```bash
python sspm.py init
```

2. Managing passwords

| Command | Description                         | Example                        |
| ------- | ----------------------------------- | ------------------------------ |
| add     | Add or overwrite a password         | python sspm.py add work/email  |
| get     | Copy password to clipboard          | python sspm.py get work/email  |
| show    | Display password in terminal        | python sspm.py show work/email |
| list    | List all passwords in a tree format | python sspm.py list            |
| rm      | Delete a password entry             | python sspm.py rm work/email   |

---

## File Structure

```
~/.sspm/
├── salt        # Unique salt for Argon2
├── validator   # Encrypted marker to validate master password
└── work/       # Your custom directories
    └── email   # Encrypted data (Nonce + Ciphertext)
```

---

**Security warning:** Never forget your master password. Because of the Argon2id derivation, there is no "password recovery" mechanism. If you lose your master key, your data is permanently unrecoverable.
