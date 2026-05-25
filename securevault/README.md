# SecureVault

SecureVault adalah aplikasi **Secure File Storage berbasis Web** yang mengimplementasikan **Hybrid Cryptography** untuk keamanan penyimpanan dan berbagi file.

---

## Features

- User Registration & Authentication# SecureVault

**SecureVault** adalah aplikasi **Secure File Storage berbasis Web** yang mengimplementasikan konsep **Hybrid Cryptography** untuk mengamankan proses penyimpanan, enkripsi, dekripsi, dan berbagi file.

Project ini dibuat menggunakan **PHP Native**, **MySQL**, dan **OpenSSL** dengan kombinasi algoritma keamanan:

- RSA-2048
- AES-256-GCM
- AES-256-CBC
- PBKDF2-SHA256
- bcrypt

---

# Fitur Utama

1. User Registration & Authentication

2. Password Hashing menggunakan bcrypt

3. RSA Key Pair Generation (RSA-2048)

3. Private Key Protection

4. File Encryption menggunakan AES-256-GCM

5. Secure File Upload & Download

6. Secure File Sharing Antar User

7. Audit Log Aktivitas

---

# Teknologi yang Digunakan

## Backend

- PHP Native
- MySQL
- OpenSSL

## Frontend

- HTML
- CSS
- JavaScript

## Cryptography

- RSA-2048
- AES-256-GCM
- AES-256-CBC
- PBKDF2-SHA256
- bcrypt

---

# Cara Kerja Sistem (Ringkas)

## Register

Saat user melakukan registrasi:

1. Password di-hash menggunakan bcrypt.
2. Sistem membuat RSA Public Key dan Private Key.
3. Private Key dienkripsi menggunakan AES-256-CBC.
4. Key enkripsi private key dibuat menggunakan PBKDF2.

---

## Upload File

Saat user mengupload file:

1. Generate random AES key.
2. File dienkripsi menggunakan AES-256-GCM.
3. AES key dienkripsi menggunakan RSA Public Key user.
4. Sistem menyimpan:
   - ciphertext file
   - encrypted AES key
   - nonce/IV
   - authentication tag

---

## Download File

Saat file diunduh:

1. AES key didekripsi menggunakan RSA Private Key.
2. File didekripsi menggunakan AES-256-GCM.
3. Authentication tag diverifikasi.
4. File asli dipulihkan.

---

## Share File

Saat file dibagikan:

1. AES key lama dibuka.
2. Public Key penerima diambil.
3. AES key dienkripsi ulang.
4. Hanya penerima yang dapat membuka file.

---

# Dependensi

Pastikan perangkat sudah memiliki:

## 1. XAMPP / Laragon / Web Server PHP

Disarankan menggunakan:

- XAMPP 8.x

atau

- Laragon

---

## 2. PHP

Versi minimum:

```txt
PHP 8.0+
```

Cek versi PHP:

```bash
php -v
```

---

## 3. MySQL / MariaDB

Versi minimum:

```txt
MySQL 5.7+
```

atau

```txt
MariaDB 10+
```

---

## 4. OpenSSL Extension

Project ini membutuhkan extension OpenSSL aktif.

Cek dengan:

```bash
php -m
```

Pastikan terdapat:

```txt
openssl
```

Jika belum aktif:

Buka file **php.ini**

hapus tanda `;`

dari:

```ini
;extension=openssl
```

menjadi:

```ini
extension=openssl
```

---

# Instalasi Project

## 1. Download / Clone Repository

Clone project:

```bash
git clone https://github.com/username/securevault.git
```

atau download ZIP repository.

---

## 2. Pindahkan ke Folder Server

Jika menggunakan XAMPP:

copy project ke:

```txt
xampp/htdocs/securevault
```

---

## 3. Jalankan Apache & MySQL

Buka:

**XAMPP Control Panel**

start:

- Apache
- MySQL

---

## 4. Import Database

Buka:

```txt
http://localhost/phpmyadmin
```

Buat database baru:

```txt
securevault
```

Kemudian import file:

```txt
database/securevault.sql
```

---

## 5. Konfigurasi Database

Buka file:

```txt
config/koneksi.php
```

Sesuaikan konfigurasi database:

```php
<?php

$conn = mysqli_connect(
    "localhost",
    "root",
    "",
    "securevault"
);

?>
```

Jika menggunakan password MySQL.

ubah bagian:

```php
""
```

menjadi password MySQL Anda.

---

# Menjalankan Aplikasi Secara Lokal

Setelah Apache dan MySQL aktif.

Buka browser:

```txt
http://localhost/securevault
```

Aplikasi siap dijalankan.

---

# Struktur Folder Project

```txt
securevault/

│
├── auth/
│   ├── login.php
│   ├── logout.php
│   └── register.php
│
├── dashboard/
│   ├── index.php
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
├── uploads/
│
├── keys/
│
├── temp/
│
└── database/
    └── securevault.sql
```

---
# Keamanan Sistem

Project ini menggunakan pendekatan **Hybrid Cryptography**.

## AES-256-GCM

Digunakan untuk:

- file encryption
- confidentiality
- integrity checking

---

## RSA-2048

Digunakan untuk:

- key encryption
- secure sharing

---

## bcrypt

Digunakan untuk:

- password hashing

---

## PBKDF2-SHA256

Digunakan untuk:

- key derivation
- private key protection

---

# Kelemahan Sistem

Beberapa keterbatasan sistem saat ini:

- Private key masih disimpan server-side.
- Belum menggunakan client-side encryption.
- Belum menggunakan HSM (Hardware Security Module).

---

# Author

Developed by:

**1.     Faija Kulla Azmina           	2488010034**
**2.     Faqih Huddin SM.             	2488010061**
**3.     Moh. Farid Ilham Ghifari 	2488010066**


Project Keamanan Informasi / Kriptografi
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
