<?php

session_start();

if (!isset($_SESSION['user_id'])) {
    header("Location: ../auth/login.php");
    exit;
}

include '../config/koneksi.php';

$user_id = (int) $_SESSION['user_id'];

if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    die("ID file tidak valid.");
}

$id = (int) $_GET['id'];

/*
==========================
AMBIL FILE + CEK OWNERSHIP - PREPARED STATEMENT
==========================
*/
$stmt = $conn->prepare("SELECT * FROM files WHERE id = ? AND user_id = ?");
$stmt->bind_param("ii", $id, $user_id);
$stmt->execute();
$file = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$file) {
    die("File tidak ditemukan atau Anda tidak memiliki akses.");
}

if (empty($file['encrypted_aes_key']) || empty($file['iv']) || empty($file['auth_tag'])) {
    die("Data enkripsi file tidak lengkap.");
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
KEY UNWRAPPING - OAEP PADDING
==========================
*/
$encrypted_key = base64_decode($file['encrypted_aes_key']);
$aes_key = '';

$ok = openssl_private_decrypt(
    $encrypted_key,
    $aes_key,
    $private_key,
    OPENSSL_PKCS1_OAEP_PADDING
);

if (!$ok) {
    die("AES key gagal didekripsi.");
}

/*
==========================
BACA FILE TERENKRIPSI
==========================
*/
$encrypted_file = "../uploads/" . $file['encrypted_name'];

if (!file_exists($encrypted_file)) {
    die("File terenkripsi tidak ditemukan.");
}

$data = file_get_contents($encrypted_file);
if ($data === false) {
    die("Gagal membaca file terenkripsi.");
}

/*
==========================
DEKRIPSI AES-256-GCM
==========================
*/
$iv  = base64_decode($file['iv']);
$tag = base64_decode($file['auth_tag']);

$decrypted = openssl_decrypt(
    $data,
    'aes-256-gcm',
    $aes_key,
    OPENSSL_RAW_DATA,
    $iv,
    $tag
);

// Bersihkan AES key
$aes_key = str_repeat("\0", strlen($aes_key));
unset($aes_key);

if ($decrypted === false) {
    die("Dekripsi gagal — auth tag GCM tidak cocok.");
}

/*
==========================
VERIFIKASI INTEGRITAS SHA-256
==========================
*/
if (!empty($file['file_hash'])) {
    $actual_hash = hash('sha256', $decrypted);
    if (!hash_equals($file['file_hash'], $actual_hash)) {
        die("PERINGATAN: Integritas file gagal! Hash tidak cocok.");
    }
}

/*
==========================
SIMPAN KE FOLDER TEMP SEMENTARA
Folder temp di luar webroot idealnya, tapi ini untuk kompatibilitas
==========================
*/
if (!file_exists("../temp")) {
    mkdir("../temp", 0700, true);
}

$temp_name = session_id() . '_' . $id . '_' . basename($file['original_name']);
$temp_file = "../temp/" . $temp_name;

file_put_contents($temp_file, $decrypted);

$ext = strtolower(pathinfo($file['original_name'], PATHINFO_EXTENSION));

// Register cleanup agar file temp dihapus setelah response
register_shutdown_function(function() use ($temp_file) {
    if (file_exists($temp_file)) {
        unlink($temp_file);
    }
});
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Preview File - SecureVault</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
<style>
body { background: #f1f5f9; padding: 30px; }
.container-box { background: white; padding: 25px; border-radius: 15px; box-shadow: 0 5px 15px rgba(0,0,0,0.1); }
iframe { width: 100%; height: 700px; border: none; }
img { max-width: 100%; border-radius: 10px; }
pre { background: #eee; padding: 20px; border-radius: 10px; overflow: auto; }
</style>
</head>
<body>
<div class="container">
<div class="container-box">

<h3 class="mb-2"><?= htmlspecialchars($file['original_name']); ?></h3>
<div class="mb-3">
  <span class="badge bg-success">Integritas: OK</span>
  <span class="badge bg-primary">AES-256-GCM</span>
</div>

<?php if (in_array($ext, ['jpg', 'jpeg', 'png', 'gif'])): ?>
  <img src="<?= htmlspecialchars($temp_file); ?>" alt="preview">

<?php elseif ($ext === 'pdf'): ?>
  <iframe src="<?= htmlspecialchars($temp_file); ?>"></iframe>

<?php elseif (in_array($ext, ['txt', 'php', 'html', 'css', 'js'])): ?>
  <pre><?= htmlspecialchars(file_get_contents($temp_file)); ?></pre>

<?php else: ?>
  <div class="alert alert-warning">
    Preview tidak tersedia untuk format <strong>.<?= htmlspecialchars($ext); ?></strong>.
    Silakan gunakan tombol Download.
  </div>
<?php endif; ?>

<br>
<a href="download.php?id=<?= $id; ?>" class="btn btn-success">Download</a>
<a href="index.php" class="btn btn-secondary">Kembali</a>
</div>
</div>
</body>
</html>
