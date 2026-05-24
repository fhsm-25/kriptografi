# SecureVault

SecureVault adalah aplikasi **Secure File Storage berbasis Web** yang mengimplementasikan **Hybrid Cryptography** untuk keamanan penyimpanan dan berbagi file.

---

## Features

- User Registration & Authentication
- Password Hashing (bcrypt)
- RSA-2048 Key Pair Generation
- Private Key Protection
- AES-256-GCM File Encryption
- Secure File Upload & Download
- Secure File Sharing
- Audit Activity Logging
- File Preview Support

---

## Technology Stack

Backend:
- PHP Native
- MySQL
- OpenSSL

Security:
- RSA-2048
- AES-256-GCM
- AES-256-CBC
- PBKDF2-SHA256
- bcrypt

Frontend:
- HTML
- CSS
- JavaScript

---

## Hybrid Cryptography Architecture

SecureVault menggunakan model **Hybrid Encryption**.

### Encryption Flow

1. User upload file.
2. Generate random AES-256 key.
3. Encrypt file menggunakan AES-256-GCM.
4. Encrypt AES key menggunakan RSA Public Key.
5. Store encrypted file.

### Decryption Flow

1. Retrieve encrypted AES key.
2. Decrypt AES key menggunakan RSA Private Key.
3. Decrypt file menggunakan AES-256-GCM.
4. Restore original file.

---

## Security Mechanisms

### Password Protection

Password disimpan menggunakan:

```php
password_hash()

securevault/

├── auth/
│   ├── login.php
│   ├── logout.php
│   └── register.php
│
├── dashboard/
│   ├── upload.php
│   ├── download.php
│   ├── preview.php
│   ├── share.php
│   ├── shared.php
│   └── audit.php
│
├── config/
│   └── koneksi.php
│
├── database/
│   └── securevault_fixed.sql
│
├── uploads/
├── keys/
└── temp/