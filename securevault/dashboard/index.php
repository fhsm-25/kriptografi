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
STATISTIK - PREPARED STATEMENTS
==========================
*/
$stmt1 = $conn->prepare("SELECT COUNT(*) as total FROM files WHERE user_id = ?");
$stmt1->bind_param("i", $user_id);
$stmt1->execute();
$total_file = $stmt1->get_result()->fetch_assoc()['total'];
$stmt1->close();

$stmt2 = $conn->prepare("SELECT COUNT(*) as total FROM shared_files WHERE owner_id = ?");
$stmt2->bind_param("i", $user_id);
$stmt2->execute();
$total_share = $stmt2->get_result()->fetch_assoc()['total'];
$stmt2->close();

/*
==========================
AMBIL DATA FILE + STATUS SHARING
==========================
*/
$stmt3 = $conn->prepare(
    "SELECT f.*,
        GROUP_CONCAT(u.username ORDER BY u.username SEPARATOR ', ') AS shared_with
     FROM files f
     LEFT JOIN shared_files sf ON f.id = sf.file_id AND sf.owner_id = f.user_id
     LEFT JOIN users u ON sf.shared_to = u.id
     WHERE f.user_id = ?
     GROUP BY f.id
     ORDER BY f.id DESC"
);
$stmt3->bind_param("i", $user_id);
$stmt3->execute();
$files = $stmt3->get_result();
$stmt3->close();
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Dashboard - SecureVault</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="../assets/css/style.css">
</head>
<body style="background:#f1f5f9;">

<nav class="navbar navbar-expand-lg navbar-dark bg-primary shadow-sm">
<div class="container">
<a class="navbar-brand fw-bold">SecureVault</a>
<div>
  <span class="text-white me-3">Halo, <?= htmlspecialchars($_SESSION['username']); ?></span>
  <a href="../auth/logout.php" class="btn btn-light btn-sm">Logout</a>
</div>
</div>
</nav>

<div class="container mt-5">
<div class="card border-0 shadow-lg p-4 rounded-4">

<div class="d-flex justify-content-between align-items-center mb-4">
<div>
  <h2 class="fw-bold">Dashboard</h2>
  <p class="text-muted">Kelola file terenkripsi anda</p>
</div>
<div>
  <a href="upload.php" class="btn btn-primary me-2">Upload File</a>
  <a href="shared.php" class="btn btn-warning">File Dibagikan</a>
  <a href="audit.php" class="btn btn-dark ms-2">Audit Log</a>
</div>
</div>

<!-- STATISTIK -->
<div class="row mb-4">
<div class="col-md-6 mb-3">
  <div class="card bg-primary text-white border-0 shadow">
    <div class="card-body">
      <h5>Total File</h5>
      <h2 class="fw-bold"><?= $total_file; ?></h2>
    </div>
  </div>
</div>
<div class="col-md-6 mb-3">
  <div class="card bg-success text-white border-0 shadow">
    <div class="card-body">
      <h5>Total Dibagikan</h5>
      <h2 class="fw-bold"><?= $total_share; ?></h2>
    </div>
  </div>
</div>
</div>

<!-- TABLE -->
<div class="table-responsive">
<table class="table table-bordered align-middle">
<thead class="table-light">
<tr>
  <th>No</th>
  <th>Nama File</th>
  <th>Tanggal Upload</th>
  <th>Status</th>
  <th>Aksi</th>
</tr>
</thead>
<tbody>
<?php
$no = 1;
while ($data = $files->fetch_assoc()):
    $is_shared = !empty($data['shared_with']);
?>
<tr>
<td width="50"><?= $no++; ?></td>
<td><?= htmlspecialchars($data['original_name']); ?></td>
<td width="220"><?= $data['created_at']; ?></td>
<td width="180">
  <span class="badge bg-success">Terenkripsi</span>
  <?php if ($is_shared): ?>
    <br><small class="text-muted">Shared: <?= htmlspecialchars($data['shared_with']); ?></small>
  <?php else: ?>
    <br><small class="text-muted">Private</small>
  <?php endif; ?>
</td>
<td width="320">
  <a href="preview.php?id=<?= $data['id']; ?>" class="btn btn-info btn-sm">Preview</a>
  <a href="download.php?id=<?= $data['id']; ?>" class="btn btn-success btn-sm">Download</a>
  <a href="share.php?id=<?= $data['id']; ?>" class="btn btn-warning btn-sm">Share</a>
  <a href="hapus.php?id=<?= $data['id']; ?>" class="btn btn-danger btn-sm"
     onclick="return confirm('Hapus file ini dan semua key material?')">Hapus</a>
</td>
</tr>
<?php endwhile; ?>
<?php if ($no === 1): ?>
<tr><td colspan="5" class="text-center text-muted">Belum ada file</td></tr>
<?php endif; ?>
</tbody>
</table>
</div>

</div>
</div>
</body>
</html>
