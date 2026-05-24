<?php

session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: ../auth/login.php");
    exit;
}

include '../config/koneksi.php';

$user_id  = (int) $_SESSION['user_id'];
$share_id = isset($_GET['id']) ? (int) $_GET['id'] : 0;

/*
==========================
AMBIL DATA SHARED FILE + CEK AKSES - PREPARED STATEMENT
==========================
*/
$stmt = $conn->prepare(
    "SELECT sf.*, f.original_name, f.encrypted_name, f.iv, f.auth_tag, f.file_hash
     FROM shared_files sf
     JOIN files f ON sf.file_id = f.id
     WHERE sf.id = ? AND sf.shared_to = ?"
);
$stmt->bind_param("ii", $share_id, $user_id);
$stmt->execute();
$data = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$data) {
    die("File share tidak ditemukan atau Anda tidak memiliki akses.");
}

/*
==========================
AMBIL PRIVATE KEY DARI SESSION
==========================
*/
if (empty($_SESSION['private_key'])) {
    die("Sesi berakhir. Silakan <a href='../auth/login.php'>login ulang</a>.");
}

$private_key = openssl_pkey_get_private($_SESSION['private_key']);

if (!$private_key) {
    die("Private key tidak valid. Silakan login ulang.");
}

/*
==========================
KEY UNWRAPPING: DEKRIPSI AES KEY DENGAN PRIVATE KEY PENERIMA
wrapped key di shared_files sudah di-wrap dengan public key penerima (saat share)
==========================
*/
$wrapped = base64_decode($data['encrypted_aes_key']);
$aes_key = '';

$ok = openssl_private_decrypt(
    $wrapped,
    $aes_key,
    $private_key,
    OPENSSL_PKCS1_OAEP_PADDING
);

if (!$ok) {
    die("Gagal mendekripsi AES key (key unwrapping).");
}

/*
==========================
BACA FILE TERENKRIPSI
==========================
*/
$file_path = "../uploads/" . $data['encrypted_name'];

if (!file_exists($file_path)) {
    die("File tidak ditemukan di server.");
}

$encrypted_data = file_get_contents($file_path);

if ($encrypted_data === false) {
    die("Gagal membaca file terenkripsi.");
}

/*
==========================
DEKRIPSI AES-256-GCM + VERIFIKASI AUTH TAG
==========================
*/
$iv       = base64_decode($data['iv']);
$auth_tag = base64_decode($data['auth_tag']);

$decrypted = openssl_decrypt(
    $encrypted_data,
    'AES-256-GCM',
    $aes_key,
    OPENSSL_RAW_DATA,
    $iv,
    $auth_tag
);

// Bersihkan AES key
$aes_key = str_repeat("\0", strlen($aes_key));
unset($aes_key);

if ($decrypted === false) {
    die("Dekripsi gagal — auth tag GCM tidak cocok. File mungkin telah dimodifikasi di server.");
}

/*
==========================
VERIFIKASI INTEGRITAS SHA-256
==========================
*/
if (!empty($data['file_hash'])) {
    $actual_hash = hash('sha256', $decrypted);
    if (!hash_equals($data['file_hash'], $actual_hash)) {
        die("PERINGATAN: Integritas file gagal! Hash SHA-256 tidak cocok.");
    }
}

/*
==========================
AUDIT LOG - PREPARED STATEMENT
==========================
*/
$stmt_log = $conn->prepare(
    "INSERT INTO audit_logs (user_id, aktivitas, nama_file) VALUES (?, 'Download Shared File', ?)"
);
$stmt_log->bind_param("is", $user_id, $data['original_name']);
$stmt_log->execute();
$stmt_log->close();

/*
==========================
KIRIM FILE
==========================
*/
while (ob_get_level()) { ob_end_clean(); }

header("Content-Description: File Transfer");
header("Content-Type: application/octet-stream");
header("Content-Disposition: attachment; filename=\"" . addslashes(basename($data['original_name'])) . "\"");
header("Content-Length: " . strlen($decrypted));
header("Cache-Control: no-store");

echo $decrypted;
exit;
?>
