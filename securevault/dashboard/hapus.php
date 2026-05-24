<?php

session_start();
include '../config/koneksi.php';

/*
==========================
CEK AUTENTIKASI - SEBELUMNYA TIDAK ADA!
==========================
*/
if (!isset($_SESSION['user_id'])) {
    header("Location: ../auth/login.php");
    exit;
}

$user_id = (int) $_SESSION['user_id'];

if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    die("ID file tidak valid.");
}

$id = (int) $_GET['id'];

/*
==========================
AMBIL DATA FILE + CEK OWNERSHIP - PREPARED STATEMENT
User hanya boleh hapus file miliknya sendiri
==========================
*/
$stmt = $conn->prepare("SELECT * FROM files WHERE id = ? AND user_id = ?");
$stmt->bind_param("ii", $id, $user_id);
$stmt->execute();
$data = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$data) {
    die("File tidak ditemukan atau Anda tidak memiliki akses.");
}

/*
==========================
HAPUS FILE TERENKRIPSI DARI DISK
==========================
*/
$file_path = "../uploads/" . $data['encrypted_name'];

if (file_exists($file_path)) {
    unlink($file_path);
}

/*
==========================
HAPUS KEY MATERIAL DI TABEL shared_files
(wrapped keys untuk semua penerima harus dihapus)
Ini penting agar penerima tidak bisa lagi mengakses file
==========================
*/
$stmt_shared = $conn->prepare("DELETE FROM shared_files WHERE file_id = ?");
$stmt_shared->bind_param("i", $id);
$stmt_shared->execute();
$stmt_shared->close();

/*
==========================
HAPUS RECORD FILE DI DATABASE - PREPARED STATEMENT
(CASCADE akan hapus shared_files juga jika FK aktif,
 tapi kita hapus manual di atas untuk kepastian)
==========================
*/
$stmt2 = $conn->prepare("DELETE FROM files WHERE id = ? AND user_id = ?");
$stmt2->bind_param("ii", $id, $user_id);
$stmt2->execute();
$stmt2->close();

/*
==========================
AUDIT LOG
==========================
*/
$stmt_log = $conn->prepare(
    "INSERT INTO audit_logs (user_id, aktivitas, nama_file) VALUES (?, 'Hapus File', ?)"
);
$stmt_log->bind_param("is", $user_id, $data['original_name']);
$stmt_log->execute();
$stmt_log->close();

echo "<script>alert('File dan seluruh key material berhasil dihapus.'); window.location='index.php';</script>";
?>
