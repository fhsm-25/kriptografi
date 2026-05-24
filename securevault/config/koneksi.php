<?php

$host = "localhost";
$user = "root";
$pass = "";
$db   = "securevault1";
$port = 3306;

$conn = mysqli_connect($host, $user, $pass, $db, $port);

if (!$conn) {
    die("Koneksi database gagal: " . mysqli_connect_error());
}

?>