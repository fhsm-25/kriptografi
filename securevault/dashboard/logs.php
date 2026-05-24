<?php

session_start();

if(!isset($_SESSION['user_id'])){

    header("Location: ../auth/login.php");
    exit;

}

include '../config/koneksi.php';

$user_id =
$_SESSION['user_id'];

$query =
mysqli_query(

$conn,

"SELECT * FROM audit_logs
WHERE user_id='$user_id'
ORDER BY id DESC"

);

?>

<!DOCTYPE html>
<html lang="id">

<head>

<meta charset="UTF-8">

<title>Riwayat Aktivitas</title>

<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css"
rel="stylesheet">

</head>

<body class="bg-light">

<div class="container py-5">

<div class="card shadow p-4">

<div class="d-flex
justify-content-between
align-items-center
mb-4">

<h3 class="fw-bold">

Riwayat Aktivitas

</h3>

<a href="index.php"
class="btn btn-primary">

Kembali

</a>

</div>

<div class="table-responsive">

<table class="table table-bordered align-middle">

<thead class="table-dark">

<tr>

<th width="70">
No
</th>

<th>
Aktivitas
</th>

<th>
Nama File
</th>

<th width="220">
Waktu
</th>

</tr>

</thead>

<tbody>

<?php

if(mysqli_num_rows($query) > 0){

$no = 1;

while(
$data =
mysqli_fetch_assoc($query)
){

?>

<tr>

<td>

<?= $no++; ?>

</td>

<td>

<?= $data['aktivitas']; ?>

</td>

<td>

<?= $data['nama_file']; ?>

</td>

<td>

<?= $data['created_at']; ?>

</td>

</tr>

<?php

}

}else{

?>

<tr>

<td colspan="4"
class="text-center text-muted">

Belum ada aktivitas

</td>

</tr>

<?php } ?>

</tbody>

</table>

</div>

</div>

</div>

</body>
</html>