<?php

session_start();
include '../config/koneksi.php';

if (!isset($_SESSION['user_id'])) {
    header("Location: ../auth/login.php");
    exit;
}

$user_id = (int) $_SESSION['user_id'];

if (!isset($_GET['id']) || !is_numeric($_GET['id'])) {
    die("ID file tidak valid.");
}

$file_id = (int) $_GET['id'];

/*
==========================
AMBIL DATA FILE + CEK OWNERSHIP - PREPARED STATEMENT
==========================
*/
$stmt = $conn->prepare("SELECT * FROM files WHERE id = ? AND user_id = ?");
$stmt->bind_param("ii", $file_id, $user_id);
$stmt->execute();
$file = $stmt->get_result()->fetch_assoc();
$stmt->close();

if (!$file) {
    die("File tidak ditemukan atau Anda tidak memiliki akses.");
}

$error   = '';
$success = '';

if (isset($_POST['share'])) {

    $shared_to = (int) $_POST['shared_to'];

    if ($shared_to === $user_id) {
        $error = 'Tidak bisa berbagi file ke diri sendiri.';
    } else {

        /*
        ==========================
        AMBIL DATA USER TUJUAN - PREPARED STATEMENT
        ==========================
        */
        $stmt2 = $conn->prepare("SELECT id, username FROM users WHERE id = ?");
        $stmt2->bind_param("i", $shared_to);
        $stmt2->execute();
        $target_user = $stmt2->get_result()->fetch_assoc();
        $stmt2->close();

        if (!$target_user) {
            $error = 'User tujuan tidak ditemukan.';
        } else {

            /*
            ==========================
            CEK APAKAH SUDAH PERNAH DI-SHARE
            ==========================
            */
            $stmt_check = $conn->prepare(
                "SELECT id FROM shared_files WHERE file_id = ? AND owner_id = ? AND shared_to = ?"
            );
            $stmt_check->bind_param("iii", $file_id, $user_id, $shared_to);
            $stmt_check->execute();
            $stmt_check->store_result();
            $already_shared = $stmt_check->num_rows > 0;
            $stmt_check->close();

            if ($already_shared) {
                $error = 'File sudah pernah dibagikan ke user ini.';
            } else {

                /*
                ==========================
                AMBIL PRIVATE KEY DARI SESSION
                ==========================
                */
                if (empty($_SESSION['private_key'])) {
                    die("Sesi berakhir. Silakan <a href='../auth/login.php'>login ulang</a>.");
                }

                $private_key_owner = openssl_pkey_get_private($_SESSION['private_key']);

                if (!$private_key_owner) {
                    die("Private key tidak valid. Silakan login ulang.");
                }

                /*
                ==========================
                KEY UNWRAPPING: DEKRIPSI AES KEY DENGAN PRIVATE KEY OWNER
                ==========================
                */
                $encrypted_aes_key = base64_decode($file['encrypted_aes_key']);
                $aes_key = '';

                $ok = openssl_private_decrypt(
                    $encrypted_aes_key,
                    $aes_key,
                    $private_key_owner,
                    OPENSSL_PKCS1_OAEP_PADDING
                );

                if (!$ok) {
                    die("Gagal mendekripsi AES key.");
                }

                /*
                ==========================
                AMBIL PUBLIC KEY USER TUJUAN
                ==========================
                */
                $public_key_path = "../keys/public_" . $shared_to . ".pem";

                if (!file_exists($public_key_path)) {
                    $error = "Public key user tujuan tidak ditemukan.";
                } else {
                    $public_key_target = openssl_pkey_get_public(file_get_contents($public_key_path));

                    if (!$public_key_target) {
                        $error = "Public key user tujuan tidak valid.";
                    } else {

                        /*
                        ==========================
                        KEY WRAPPING ULANG: ENKRIPSI AES KEY DENGAN PUBLIC KEY PENERIMA
                        Ini adalah inti dari key wrapping — AES key yang sama
                        dibungkus ulang untuk penerima yang berbeda.
                        File fisik hanya satu salinan, tapi setiap penerima
                        punya wrapped key yang hanya bisa dibuka dengan private key-nya.
                        ==========================
                        */
                        $wrapped_key = '';
                        $ok2 = openssl_public_encrypt(
                            $aes_key,
                            $wrapped_key,
                            $public_key_target,
                            OPENSSL_PKCS1_OAEP_PADDING
                        );

                        // Bersihkan AES key
                        $aes_key = str_repeat("\0", strlen($aes_key));
                        unset($aes_key);

                        if (!$ok2) {
                            $error = "Key wrapping untuk penerima gagal.";
                        } else {

                            $wrapped_key_b64 = base64_encode($wrapped_key);

                            /*
                            ==========================
                            SIMPAN KE DATABASE - PREPARED STATEMENT
                            ==========================
                            */
                            $stmt3 = $conn->prepare(
                                "INSERT INTO shared_files (file_id, owner_id, shared_to, encrypted_aes_key)
                                 VALUES (?, ?, ?, ?)"
                            );
                            $stmt3->bind_param("iiis", $file_id, $user_id, $shared_to, $wrapped_key_b64);

                            if ($stmt3->execute()) {
                                $stmt3->close();

                                /*
                                ==========================
                                AUDIT LOG
                                ==========================
                                */
                                $stmt_log = $conn->prepare(
                                    "INSERT INTO audit_logs (user_id, aktivitas, nama_file)
                                     VALUES (?, 'Share File', ?)"
                                );
                                $nama = $file['original_name'] . ' → ' . $target_user['username'];
                                $stmt_log->bind_param("is", $user_id, $nama);
                                $stmt_log->execute();
                                $stmt_log->close();

                                $success = "File berhasil dibagikan ke " . htmlspecialchars($target_user['username']) . ".";
                            } else {
                                $error = "Gagal menyimpan ke database: " . $stmt3->error;
                                $stmt3->close();
                            }
                        }
                    }
                }
            }
        }
    }
}

/*
==========================
AMBIL DAFTAR USER LAIN UNTUK DROPDOWN
==========================
*/
$stmt_users = $conn->prepare("SELECT id, username FROM users WHERE id != ? ORDER BY username ASC");
$stmt_users->bind_param("i", $user_id);
$stmt_users->execute();
$users_result = $stmt_users->get_result();
$stmt_users->close();

/*
==========================
AMBIL DAFTAR SUDAH DIBAGIKAN KE SIAPA
==========================
*/
$stmt_shared = $conn->prepare(
    "SELECT u.username, sf.shared_at
     FROM shared_files sf
     JOIN users u ON sf.shared_to = u.id
     WHERE sf.file_id = ? AND sf.owner_id = ?
     ORDER BY sf.shared_at DESC"
);
$stmt_shared->bind_param("ii", $file_id, $user_id);
$stmt_shared->execute();
$shared_list = $stmt_shared->get_result()->fetch_all(MYSQLI_ASSOC);
$stmt_shared->close();
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Share File - SecureVault</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
</head>
<body class="bg-light">
<div class="container py-5">
<div class="card shadow">
<div class="card-header">
  <h4>Share File: <em><?= htmlspecialchars($file['original_name']); ?></em></h4>
</div>
<div class="card-body">

<?php if ($error): ?>
<div class="alert alert-danger"><?= htmlspecialchars($error); ?></div>
<?php endif; ?>
<?php if ($success): ?>
<div class="alert alert-success"><?= htmlspecialchars($success); ?></div>
<?php endif; ?>

<div class="alert alert-info small">
  <strong>Key Wrapping:</strong> AES session key akan dienkripsi ulang dengan public key penerima.
  File fisik tidak digandakan — hanya wrapped key yang berbeda untuk setiap penerima.
</div>

<form method="POST">
<div class="mb-3">
  <label class="form-label">Bagikan ke User</label>
  <select name="shared_to" class="form-control" required>
    <option value="">-- Pilih User --</option>
    <?php while ($u = $users_result->fetch_assoc()): ?>
    <option value="<?= $u['id']; ?>"><?= htmlspecialchars($u['username']); ?></option>
    <?php endwhile; ?>
  </select>
</div>
<button type="submit" name="share" class="btn btn-primary">Share File</button>
<a href="index.php" class="btn btn-secondary">Kembali</a>
</form>

<?php if (!empty($shared_list)): ?>
<hr>
<h6>Sudah dibagikan ke:</h6>
<ul class="list-group">
<?php foreach ($shared_list as $s): ?>
<li class="list-group-item d-flex justify-content-between align-items-center">
  <?= htmlspecialchars($s['username']); ?>
  <small class="text-muted"><?= $s['shared_at']; ?></small>
</li>
<?php endforeach; ?>
</ul>
<?php endif; ?>

</div>
</div>
</div>
</body>
</html>
