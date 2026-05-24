<?php

session_start();
include '../config/koneksi.php';

$error = '';

if (isset($_POST['login'])) {

    $username = trim($_POST['username']);
    $password = $_POST['password'];

    if (empty($username) || empty($password)) {
        $error = 'Username dan password wajib diisi.';
    } else {

        /*
        ==========================
        CEK USERNAME - PREPARED STATEMENT
        ==========================
        */
        $stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
        $stmt->bind_param("s", $username);
        $stmt->execute();
        $result = $stmt->get_result();
        $data   = $result->fetch_assoc();
        $stmt->close();

        if (!$data) {
            $error = 'Username tidak ditemukan.';
        } elseif (!password_verify($password, $data['password'])) {
            $error = 'Password salah.';
        } else {

            /*
            ==========================
            DEKRIPSI PRIVATE KEY MENGGUNAKAN PASSWORD USER
            Private key disimpan terenkripsi di DB (format: salt|iv|ciphertext)
            Hanya bisa dibuka dengan password yang benar.
            ==========================
            */
            $parts = explode('|', $data['private_key_encrypted']);

            if (count($parts) !== 3) {
                $error = 'Data private key rusak. Hubungi administrator.';
            } else {
                $salt_pkey = base64_decode($parts[0]);
                $iv_pkey   = base64_decode($parts[1]);
                $enc_pkey  = base64_decode($parts[2]);

                // Derive key yang sama dari password
                $enc_key = hash_pbkdf2('sha256', $password, $salt_pkey, 100000, 32, true);

                $private_key_plain = openssl_decrypt(
                    $enc_pkey,
                    'AES-256-CBC',
                    $enc_key,
                    OPENSSL_RAW_DATA,
                    $iv_pkey
                );

                if ($private_key_plain === false) {
                    $error = 'Gagal mendekripsi private key.';
                } else {
                    // Verifikasi private key valid
                    $pk_resource = openssl_pkey_get_private($private_key_plain);
                    if (!$pk_resource) {
                        $error = 'Private key tidak valid.';
                        unset($private_key_plain);
                    } else {
                        /*
                        ==========================
                        SIMPAN KE SESSION
                        Private key plaintext disimpan di session server-side
                        (tidak pernah dikirim ke client / disimpan di DB plaintext)
                        ==========================
                        */
                        session_regenerate_id(true);

                        $_SESSION['user_id']    = $data['id'];
                        $_SESSION['username']   = $data['username'];
                        $_SESSION['private_key'] = $private_key_plain;

                        // Bersihkan variabel sensitif
                        unset($private_key_plain, $enc_key);

                        /*
                        ==========================
                        AUDIT LOG
                        ==========================
                        */
                        $stmt_log = $conn->prepare(
                            "INSERT INTO audit_logs (user_id, aktivitas, nama_file) VALUES (?, 'Login', '-')"
                        );
                        $stmt_log->bind_param("i", $data['id']);
                        $stmt_log->execute();
                        $stmt_log->close();

                        header("Location: ../dashboard/index.php");
                        exit;
                    }
                }
            }
        }
    }
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Masuk - SecureVault</title>
<link href="https://cdn.jsdelivr.net/npm/bootstrap@5.0.2/dist/css/bootstrap.min.css" rel="stylesheet">
<link rel="stylesheet" href="../assets/css/style.css">
</head>
<body>
<div class="container">
<div class="row justify-content-center align-items-center vh-100">
<div class="col-md-5">
<div class="card auth-card p-4">
<div class="card-body">
<h2 class="text-center brand-title mb-3">SecureVault</h2>
<p class="text-center text-muted mb-4">Masuk ke akun anda</p>

<?php if ($error): ?>
<div class="alert alert-danger"><?= htmlspecialchars($error); ?></div>
<?php endif; ?>

<form method="POST">
<div class="mb-3">
  <label class="mb-2">Username</label>
  <input type="text" name="username" class="form-control" required
         value="<?= isset($_POST['username']) ? htmlspecialchars($_POST['username']) : ''; ?>">
</div>
<div class="mb-4">
  <label class="mb-2">Password</label>
  <input type="password" name="password" class="form-control" required>
</div>
<button type="submit" name="login" class="btn btn-primary btn-custom w-100">Masuk</button>
</form>

<div class="text-center mt-3">
  Belum punya akun? <a href="register.php">Daftar</a>
</div>
</div>
</div>
</div>
</div>
</div>
</body>
</html>
