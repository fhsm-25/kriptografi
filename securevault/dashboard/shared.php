<?php

session_start();
include '../config/koneksi.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: ../auth/login.php");
    exit;
}

$user_id = (int) $_SESSION['user_id'];

/*
==========================
AMBIL FILE YANG DIBAGIKAN KE USER INI - PREPARED STATEMENT
==========================
*/
$stmt = $conn->prepare(
    "SELECT sf.id, sf.shared_at,
            f.original_name,
            u.username AS owner_name
     FROM shared_files sf
     JOIN files f ON sf.file_id = f.id
     JOIN users u ON sf.owner_id = u.id
     WHERE sf.shared_to = ?
     ORDER BY sf.id DESC"
);
$stmt->bind_param("i", $user_id);
$stmt->execute();
$result = $stmt->get_result();
$stmt->close();
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>File Dibagikan - SecureVault</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-5">
<div class="card shadow p-4">
<div class="d-flex justify-content-between align-items-center mb-4">
  <h3>File Yang Dibagikan Ke Saya</h3>
  <a href="index.php" class="btn btn-primary">Kembali ke Dashboard</a>
</div>

<div class="table-responsive">
<table class="table table-bordered">
<thead class="table-light">
<tr>
  <th>No</th>
  <th>Nama File</th>
  <th>Dari User</th>
  <th>Tanggal</th>
  <th>Aksi</th>
</tr>
</thead>
<tbody>
<?php
$no = 1;
while ($data = $result->fetch_assoc()):
?>
<tr>
<td><?= $no++; ?></td>
<td><?= htmlspecialchars($data['original_name']); ?></td>
<td><?= htmlspecialchars($data['owner_name']); ?></td>
<td><?= $data['shared_at']; ?></td>
<td>
  <a href="download_shared.php?id=<?= $data['id']; ?>" class="btn btn-success btn-sm">Download</a>
</td>
</tr>
<?php endwhile; ?>
<?php if ($no === 1): ?>
<tr><td colspan="5" class="text-center">Belum ada file yang dibagikan ke Anda</td></tr>
<?php endif; ?>
</tbody>
</table>
</div>
</div>
</div>
</body>
</html>
