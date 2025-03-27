# Termanager - Advanced Terminal Password Manager

## Overview

Termanager is a secure, command-line password management solution designed for professionals who demand robust security and terminal-based efficiency. This application combines military-grade encryption with two-factor authentication to provide a secure vault for credential storage.

## Key Features

- **AES-256 Encryption**: All passwords are encrypted using PBKDF2 key derivation with SHA-256 and AES-256 in CBC mode
- **Two-Factor Authentication**: Time-based OTP (TOTP) support for enhanced security
- **Password Expiration**: Optional automatic password expiration policies
- **Secure Storage**: Encrypted credential storage with salt randomization
- **Password Generation**: Strong random password generation capabilities
- **Import/Export**: Secure data migration capabilities with maintained encryption
- **Cross-Platform**: Compatible with any system supporting Python 3.7+

## Installation

### Python Package Installation

```bash
pip install git+https://github.com/linuxfanboy4/termmanager
```

### Docker Container

```bash
docker pull ghcr.io/linuxfanboy4/termanager:latest
docker run -it ghcr.io/linuxfanboy4/termanager:latest
```

## Usage

### Initial Setup

On first run, Termanager will guide you through:
1. Setting a master password (SHA-256 hashed)
2. Configuring TOTP two-factor authentication
3. Creating secure storage files

### Command Reference

```
usage: termanager.py action [options]

Available actions:
  add         Add a new password entry
  get         Retrieve a stored password
  delete      Remove a password entry
  update      Change an existing password
  generate    Create a strong random password
  export      Export decrypted data (requires master password)
  import      Import encrypted data

Required arguments:
  --master_password    Master password for encryption/decryption

Optional arguments:
  --account            Account name for password operations
  --password           Password for account operations
  --new_password       New password for update operations
```

### Example Workflows

**Adding a new credential:**
```bash
termanager add --account example.com --password secure123 --master_password your_master_password
```

**Retrieving a password:**
```bash
termanager get --account example.com --master_password your_master_password
```

**Generating a strong password:**
```bash
termanager generate
```

## Security Architecture

### Encryption Implementation

1. **Key Derivation**: PBKDF2-HMAC-SHA256 with 200,000 iterations
2. **Encryption**: AES-256 in CBC mode with random IV for each encryption
3. **Padding**: PKCS7-style padding for block alignment
4. **Storage**: Base64 encoded ciphertext with IV prepended

### Authentication Layers

1. **Master Password**: SHA-256 hashed storage with 3 attempt limit
2. **TOTP Verification**: 30-second time-based one-time passwords
3. **Session Management**: Memory-only master key with reauthentication required

## Data Management

- **Password Expiry**: Configurable expiration dates (default 365 days)
- **Secure Export**: Decrypted only during export with master password
- **Import Safety**: Re-encryption during import with current master key

### Dependencies

- cryptography
- pyotp
- argparse

## License

MIT License. See `LICENSE` file for full terms.

## Security Considerations

1. Always use a strong master password (minimum 16 characters)
2. Secure your TOTP secret during initial setup
3. Regularly export backups to secure storage
4. Never share your master password or TOTP device
5. Consider physical security for devices running Termanager

## Support

For security issues, please report via GitHub issues with appropriate sensitivity. For feature requests or bug reports, use standard GitHub issue tracking.
