<?php

session_start();
include '../config/koneksi.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: ../auth/login.php");
    exit;
}

$user_id = (int) $_SESSION['user_id'];
$error   = '';

if (isset($_POST['upload'])) {

    /*
    ==========================
    VALIDASI FILE
    ==========================
    */
    $allowed = ['pdf', 'docx', 'xlsx', 'pptx', 'jpg', 'jpeg', 'png'];

    $file_name = $_FILES['file']['name'];
    $tmp_name  = $_FILES['file']['tmp_name'];
    $file_size = $_FILES['file']['size'];

    $ext = strtolower(pathinfo($file_name, PATHINFO_EXTENSION));

    if (!in_array($ext, $allowed)) {
        die("Format file tidak diizinkan.");
    }

    if ($file_size > 10 * 1024 * 1024) {
        die("Ukuran file maksimal 10MB.");
    }

    if (!is_uploaded_file($tmp_name)) {
        die("File upload tidak valid.");
    }

    /*
    ==========================
    AMBIL PUBLIC KEY USER DARI FILE
    ==========================
    */
    if (!file_exists("../keys")) {
        mkdir("../keys", 0700, true);
    }

    $public_key_path = "../keys/public_" . $user_id . ".pem";

    if (!file_exists($public_key_path)) {
        die("Public key user tidak ditemukan. Coba login ulang.");
    }

    $public_key = openssl_pkey_get_public(file_get_contents($public_key_path));

    if (!$public_key) {
        die("Public key gagal dibaca.");
    }

    /*
    ==========================
    BACA FILE & HITUNG SHA-256 HASH
    (untuk verifikasi integritas saat download)
    ==========================
    */
    $file_data  = file_get_contents($tmp_name);
    $file_hash  = hash('sha256', $file_data);

    /*
    ==========================
    GENERATE AES SESSION KEY (32 byte = 256 bit)
    Key baru unik untuk setiap file
    ==========================
    */
    $aes_key = openssl_random_pseudo_bytes(32);

    /*
    ==========================
    ENKRIPSI FILE: AES-256-GCM
    GCM memberikan authenticated encryption:
    - Confidentiality (tidak bisa dibaca tanpa kunci)
    - Integrity (auth tag mendeteksi modifikasi)
    ==========================
    */
    $iv  = openssl_random_pseudo_bytes(12);  // 96-bit IV standar GCM
    $tag = '';

    $encrypted_data = openssl_encrypt(
        $file_data,
        'aes-256-gcm',
        $aes_key,
        OPENSSL_RAW_DATA,
        $iv,
        $tag,
        '',
        16  // tag length 128-bit
    );

    if ($encrypted_data === false) {
        die("Enkripsi file gagal.");
    }

    /*
    ==========================
    SIMPAN FILE TERENKRIPSI
    ==========================
    */
    if (!file_exists("../uploads")) {
        mkdir("../uploads", 0700, true);
    }

    $encrypted_filename = time() . '_' . bin2hex(openssl_random_pseudo_bytes(4)) . ".enc";
    $upload_path = "../uploads/" . $encrypted_filename;

    if (file_put_contents($upload_path, $encrypted_data) === false) {
        die("Gagal menyimpan file terenkripsi.");
    }

    /*
    ==========================
    KEY WRAPPING: ENKRIPSI AES KEY DENGAN RSA-OAEP
    Session key di-wrap dengan public key owner.
    Hanya private key owner yang bisa membuka AES key ini.
    Menggunakan OAEP padding (lebih aman dari PKCS#1 v1.5)
    ==========================
    */
    $encrypted_key = '';
    $ok = openssl_public_encrypt(
        $aes_key,
        $encrypted_key,
        $public_key,
        OPENSSL_PKCS1_OAEP_PADDING
    );

    if (!$ok) {
        // Hapus file yang sudah diupload jika key wrapping gagal
        unlink($upload_path);
        die("Enkripsi AES key (key wrapping) gagal.");
    }

    // Encode untuk penyimpanan database
    $encrypted_key_b64 = base64_encode($encrypted_key);
    $iv_b64            = base64_encode($iv);
    $tag_b64           = base64_encode($tag);

    // Bersihkan AES key dari memori
    $aes_key = str_repeat("\0", strlen($aes_key));
    unset($aes_key);

    /*
    ==========================
    SIMPAN KE DATABASE - PREPARED STATEMENT
    ==========================
    */
    $stmt = $conn->prepare(
        "INSERT INTO files (user_id, original_name, encrypted_name, encrypted_aes_key, iv, auth_tag, file_hash)
         VALUES (?, ?, ?, ?, ?, ?, ?)"
    );
    $stmt->bind_param(
        "issssss",
        $user_id,
        $file_name,
        $encrypted_filename,
        $encrypted_key_b64,
        $iv_b64,
        $tag_b64,
        $file_hash
    );

    if (!$stmt->execute()) {
        unlink($upload_path);
        die("Gagal simpan ke database: " . $stmt->error);
    }
    $stmt->close();

    /*
    ==========================
    AUDIT LOG
    ==========================
    */
    $stmt_log = $conn->prepare(
        "INSERT INTO audit_logs (user_id, aktivitas, nama_file) VALUES (?, 'Upload File', ?)"
    );
    $stmt_log->bind_param("is", $user_id, $file_name);
    $stmt_log->execute();
    $stmt_log->close();

    echo "<script>alert('File berhasil diupload dan dienkripsi!'); window.location='index.php';</script>";
    exit;
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Upload File - SecureVault</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-5">
<div class="card shadow">
<div class="card-header"><h4>Upload File Aman</h4></div>
<div class="card-body">
<div class="alert alert-info small">
  File akan dienkripsi dengan <strong>AES-256-GCM</strong> menggunakan session key acak.
  Session key di-wrap dengan <strong>RSA-2048-OAEP</strong> menggunakan kunci publik Anda.
</div>
<form method="POST" enctype="multipart/form-data">
<div class="mb-3">
  <label class="form-label">Pilih File</label>
  <input type="file" name="file" class="form-control" required>
  <small class="text-muted">Format: PDF, DOCX, XLSX, PPTX, JPG, PNG | Maks: 10MB</small>
</div>
<button type="submit" name="upload" class="btn btn-primary">Upload & Enkripsi</button>
<a href="index.php" class="btn btn-secondary">Kembali</a>
</form>
</div>
</div>
</div>
</body>
</html>
