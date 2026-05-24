<?php

/*
==========================
FIX OPENSSL WINDOWS XAMPP
==========================
*/
putenv("OPENSSL_CONF=C:/xampp/php/extras/ssl/openssl.cnf");

session_start();
include '../config/koneksi.php';

$error   = '';
$success = '';

if (isset($_POST['register'])) {

    $username = trim($_POST['username']);
    $password = $_POST['password'];

    /*
    ==========================
    VALIDASI INPUT
    ==========================
    */
    if (empty($username) || empty($password)) {
        $error = 'Username dan password wajib diisi.';
    } elseif (strlen($password) < 6) {
        $error = 'Password minimal 6 karakter.';
    } else {

        /*
        ==========================
        CEK USERNAME - PREPARED STATEMENT
        ==========================
        */
        $stmt = $conn->prepare("SELECT id FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $stmt->store_result();

        if ($stmt->num_rows > 0) {
            $error = 'Username sudah digunakan.';
            $stmt->close();
        } else {
            $stmt->close();

            /*
            ==========================
            HASH PASSWORD (BCRYPT)
            ==========================
            */
            $hash = password_hash($password, PASSWORD_BCRYPT);

            /*
            ==========================
            GENERATE RSA-2048 KEY PAIR
            ==========================
            */
            $config = [
                "config"           => "C:/xampp/php/extras/ssl/openssl.cnf",
                "private_key_bits" => 2048,
                "private_key_type" => OPENSSL_KEYTYPE_RSA,
            ];

            $res = openssl_pkey_new($config);
            if (!$res) {
                die("Generate RSA gagal: " . openssl_error_string());
            }

            $details    = openssl_pkey_get_details($res);
            $public_key = $details['key'];

            $export = openssl_pkey_export($res, $private_key_plain, null, $config);
            if (!$export || empty($private_key_plain)) {
                die("Export private key gagal: " . openssl_error_string());
            }

            /*
            ==========================
            ENKRIPSI PRIVATE KEY DENGAN PASSWORD USER
            Algoritma: PBKDF2-SHA256 (100.000 iterasi) -> AES-256-CBC
            Tujuan: private key hanya bisa dibuka oleh user yang tahu passwordnya.
            Jika database bocor, private key tetap tidak bisa dibaca tanpa password.
            ==========================
            */
            $salt_pkey = openssl_random_pseudo_bytes(16);
            $iter      = 100000;
            $enc_key   = hash_pbkdf2('sha256', $password, $salt_pkey, $iter, 32, true);
            $iv_pkey   = openssl_random_pseudo_bytes(16);

            $encrypted_private_key = openssl_encrypt(
                $private_key_plain,
                'AES-256-CBC',
                $enc_key,
                OPENSSL_RAW_DATA,
                $iv_pkey
            );

            if ($encrypted_private_key === false) {
                die("Enkripsi private key gagal.");
            }

            // Format simpan: base64(salt)|base64(iv)|base64(ciphertext)
            $private_key_stored =
                base64_encode($salt_pkey) . '|' .
                base64_encode($iv_pkey)   . '|' .
                base64_encode($encrypted_private_key);

            // Bersihkan plaintext dari memori
            $private_key_plain = str_repeat("\0", strlen($private_key_plain));
            unset($private_key_plain, $enc_key);

            /*
            ==========================
            SIMPAN USER - PREPARED STATEMENT
            ==========================
            */
            $stmt2 = $conn->prepare(
                "INSERT INTO users (username, password, public_key, private_key_encrypted)
                 VALUES (?, ?, ?, ?)"
            );
            $stmt2->bind_param("ssss", $username, $hash, $public_key, $private_key_stored);
            $insert = $stmt2->execute();

            if (!$insert) {
                die("Gagal simpan user: " . $stmt2->error);
            }

            $user_id = $conn->insert_id;
            $stmt2->close();

            /*
            ==========================
            SIMPAN PUBLIC KEY KE FILE
            (Private key TIDAK disimpan plaintext di file maupun DB)
            ==========================
            */
            if (!file_exists("../keys")) {
                mkdir("../keys", 0700, true);
            }
            file_put_contents("../keys/public_" . $user_id . ".pem", $public_key);

            /*
            ==========================
            AUDIT LOG
            ==========================
            */
            $stmt_log = $conn->prepare(
                "INSERT INTO audit_logs (user_id, aktivitas, nama_file) VALUES (?, 'Registrasi Akun', '-')"
            );
            $stmt_log->bind_param("i", $user_id);
            $stmt_log->execute();
            $stmt_log->close();

            $success = 'Registrasi berhasil! Silakan login.';
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Daftar - SecureVault</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="../assets/css/style.css">
</head>
<body>
<div class="container">
<div class="row justify-content-center align-items-center vh-100">
<div class="col-md-5">
<div class="card auth-card p-4 shadow">
<div class="card-body">
<h2 class="text-center brand-title mb-3">SecureVault</h2>
<p class="text-center text-muted mb-4">Buat akun baru</p>

<?php if ($error): ?>
<div class="alert alert-danger"><?= htmlspecialchars($error); ?></div>
<?php endif; ?>
<?php if ($success): ?>
<div class="alert alert-success">
  <?= htmlspecialchars($success); ?> <a href="login.php">Klik di sini untuk login</a>
</div>
<?php endif; ?>

<form method="POST">
<div class="mb-3">
  <label class="mb-2">Username</label>
  <input type="text" name="username" class="form-control" required
         value="<?= isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>">
</div>
<div class="mb-4">
  <label class="mb-2">Password <small class="text-muted">(min. 6 karakter)</small></label>
  <input type="password" name="password" class="form-control" required>
</div>
<button type="submit" name="register" class="btn btn-primary w-100">Daftar</button>
</form>

<div class="text-center mt-3">
  Sudah punya akun? <a href="login.php">Masuk</a>
</div>
</div>
</div>
</div>
</div>
</div>
</body>
</html>
