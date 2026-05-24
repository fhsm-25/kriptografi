<?php

session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: ../auth/login.php");
    exit;
}

include '../config/koneksi.php';

$user_id = (int) $_SESSION['user_id'];

/*
==========================
VALIDASI INPUT
==========================
*/
if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    die("ID file tidak valid.");
}

$id = (int) $_GET['id'];

/*
==========================
AMBIL DATA FILE + CEK OWNERSHIP - PREPARED STATEMENT
User hanya boleh download file miliknya sendiri
==========================
*/
$stmt = $conn->prepare(
    "SELECT * FROM files WHERE id = ? AND user_id = ?"
);
$stmt->bind_param("ii", $id, $user_id);
$stmt->execute();
$data = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$data) {
    die("File tidak ditemukan atau Anda tidak memiliki akses.");
}

/*
==========================
AMBIL PRIVATE KEY DARI SESSION
(Didekripsi saat login, disimpan di session server-side)
==========================
*/
if (empty($_SESSION['private_key'])) {
    die("Sesi berakhir. Silakan <a href='../auth/login.php'>login ulang</a>.");
}

$private_key_resource = openssl_pkey_get_private($_SESSION['private_key']);

if (!$private_key_resource) {
    die("Private key tidak valid. Silakan login ulang.");
}

/*
==========================
KEY UNWRAPPING: DEKRIPSI AES KEY DENGAN RSA-OAEP
Menggunakan OAEP padding (konsisten dengan upload)
==========================
*/
$rsa_encrypted_key = base64_decode($data['encrypted_aes_key']);
$aes_key = '';

$ok = openssl_private_decrypt(
    $rsa_encrypted_key,
    $aes_key,
    $private_key_resource,
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
    die("File fisik tidak ditemukan di server.");
}

$encrypted_data = file_get_contents($file_path);

if ($encrypted_data === false) {
    die("Gagal membaca file terenkripsi.");
}

/*
==========================
AMBIL IV & AUTH TAG
==========================
*/
$iv  = base64_decode($data['iv']);
$tag = base64_decode($data['auth_tag']);

if (empty($iv) || empty($tag)) {
    die("IV atau auth tag rusak.");
}

/*
==========================
DEKRIPSI FILE: AES-256-GCM
Auth tag otomatis diverifikasi oleh GCM.
Jika file dimodifikasi di server, openssl_decrypt akan return false.
==========================
*/
$decrypted_data = openssl_decrypt(
    $encrypted_data,
    'aes-256-gcm',
    $aes_key,
    OPENSSL_RAW_DATA,
    $iv,
    $tag
);

// Bersihkan AES key dari memori
$aes_key = str_repeat("\0", strlen($aes_key));
unset($aes_key);

if ($decrypted_data === false) {
    die("Dekripsi gagal — auth tag GCM tidak cocok. File mungkin telah dimodifikasi di server.");
}

/*
==========================
VERIFIKASI INTEGRITAS: SHA-256 HASH
Lapisan kedua verifikasi selain GCM auth tag
==========================
*/
if (!empty($data['file_hash'])) {
    $actual_hash = hash('sha256', $decrypted_data);
    if (!hash_equals($data['file_hash'], $actual_hash)) {
        die("PERINGATAN: Integritas file gagal! Hash SHA-256 tidak cocok. File telah dimodifikasi.");
    }
}

/*
==========================
AUDIT LOG - PREPARED STATEMENT
==========================
*/
$stmt_log = $conn->prepare(
    "INSERT INTO audit_logs (user_id, aktivitas, nama_file) VALUES (?, 'Download File', ?)"
);
$stmt_log->bind_param("is", $user_id, $data['original_name']);
$stmt_log->execute();
$stmt_log->close();

/*
==========================
KIRIM FILE KE BROWSER
==========================
*/
while (ob_get_level()) {
    ob_end_clean();
}

header('Content-Description: File Transfer');
header('Content-Type: application/octet-stream');
header('Content-Disposition: attachment; filename="' . addslashes(basename($data['original_name'])) . '"');
header('Content-Length: ' . strlen($decrypted_data));
header('Cache-Control: no-store, no-cache');
header('Pragma: no-cache');

echo $decrypted_data;
exit;
?>
