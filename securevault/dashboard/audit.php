<?php
// dashboard/audit.php
session_start();
if (!isset($_SESSION['user_id'])) { header("Location: ../auth/login.php"); exit; }
include '../config/koneksi.php';

$user_id = (int) $_SESSION['user_id'];

$stmt = $conn->prepare("SELECT * FROM audit_logs WHERE user_id = ? ORDER BY created_at DESC LIMIT 100");
$stmt->bind_param("i", $user_id);
$stmt->execute();
$logs = $stmt->get_result()->fetch_all(MYSQLI_ASSOC);

function activityIcon($act) {
    $map = ['Upload File'=>['⬆️','#4f8ef7'],'Download File'=>['⬇️','#10b981'],'Download Shared File'=>['⬇️','#10b981'],'Share File'=>['🔗','#f59e0b'],'Hapus File'=>['🗑️','#ef4444']];
    return $map[$act] ?? ['📋','#64748b'];
}
?>
<!DOCTYPE html>
<html lang="id">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Riwayat Aktivitas — SecureVault</title>
<link rel="preconnect" href="https://fonts.googleapis.com">
<link href="https://fonts.googleapis.com/css2?family=DM+Sans:wght@300;400;500;600&family=Syne:wght@700;800&display=swap" rel="stylesheet">
<style>
*, *::before, *::after{
    box-sizing:border-box;
    margin:0;
    padding:0;
}

:root{
    --bg:#f3f4f6;
    --sidebar-bg:#ffffff;
    --surface:#ffffff;
    --surface2:#f8fafc;

    --border:#d1d5db;
    --border2:#e5e7eb;

    --accent:#2563eb;
    --accent2:#1d4ed8;

    --text:#111827;
    --muted:#6b7280;
    --muted2:#374151;

    --danger:#dc2626;

    --sidebar-w:260px;
}

body{
    font-family:'DM Sans',sans-serif;
    background:var(--bg);
    color:var(--text);
    min-height:100vh;
    display:flex;
}

/* SIDEBAR */

.sidebar{
    width:var(--sidebar-w);
    background:var(--sidebar-bg);
    border-right:1px solid var(--border);
    position:fixed;
    top:0;
    left:0;
    bottom:0;
    padding:24px 16px;
    display:flex;
    flex-direction:column;
}

.sidebar-logo{
    display:flex;
    align-items:center;
    gap:10px;
    margin-bottom:32px;
}

.logo-icon{
    width:38px;
    height:38px;
    border-radius:10px;
    background:linear-gradient(135deg,#2563eb,#3b82f6);
    display:flex;
    align-items:center;
    justify-content:center;
}

.logo-text{
    font-family:'Syne',sans-serif;
    font-size:22px;
    font-weight:800;
}

.logo-badge{
    background:#2563eb;
    color:white;
    padding:3px 8px;
    border-radius:20px;
    font-size:10px;
}

.nav-label{
    font-size:12px;
    color:var(--muted);
    text-transform:uppercase;
    margin-bottom:8px;
}

.nav-item{
    display:flex;
    align-items:center;
    gap:10px;
    padding:12px 14px;
    border-radius:10px;
    text-decoration:none;
    color:#374151;
    margin-bottom:6px;
    transition:.2s;
}

.nav-item:hover{
    background:#eff6ff;
    color:#2563eb;
}

.nav-item.active{
    background:#dbeafe;
    color:#2563eb;
    font-weight:600;
}

/* USER */

.sidebar-bottom{
    margin-top:auto;
}

.user-info{
    display:flex;
    align-items:center;
    gap:10px;
    padding:12px;
    border-radius:14px;
    background:#f9fafb;
    border:1px solid var(--border);
}

.avatar{
    width:40px;
    height:40px;
    border-radius:50%;
    background:#2563eb;
    color:white;
    display:flex;
    justify-content:center;
    align-items:center;
    font-weight:700;
}

.user-name{
    font-weight:600;
}

.user-role{
    font-size:12px;
    color:var(--muted);
}

.logout-btn{
    margin-left:auto;
    text-decoration:none;
    color:#6b7280;
}

.logout-btn:hover{
    color:var(--danger);
}

/* MAIN */

.main{
    margin-left:var(--sidebar-w);
    flex:1;
    padding:40px;
}

.page-title{
    font-family:'Syne',sans-serif;
    font-size:42px;
    font-weight:800;
    margin-bottom:10px;
}

.page-sub{
    color:var(--muted);
    margin-bottom:40px;
    font-size:18px;
}

/* TIMELINE */

.timeline{
    max-width:900px;
}

.tl-item{
    display:flex;
    gap:18px;
    position:relative;
    padding-bottom:24px;
}

.tl-item::before{
    content:'';
    position:absolute;
    left:22px;
    top:45px;
    bottom:0;
    width:2px;
    background:#dbeafe;
}

.tl-item:last-child::before{
    display:none;
}

.tl-icon{
    width:46px;
    height:46px;
    border-radius:50%;
    display:flex;
    align-items:center;
    justify-content:center;
    font-size:18px;
    flex-shrink:0;
    z-index:2;
}

.tl-body{
    flex:1;
    background:white;
    border:1px solid var(--border);
    border-radius:16px;
    padding:20px;
    box-shadow:0 6px 20px rgba(0,0,0,0.05);
}

.tl-activity{
    font-size:20px;
    font-weight:700;
    margin-bottom:8px;
}

.tl-file{
    color:var(--muted2);
    margin-bottom:8px;
}

.tl-time{
    color:var(--muted);
    font-size:14px;
}

/* EMPTY */

.empty-state{
    text-align:center;
    background:white;
    border-radius:20px;
    padding:80px 30px;
    border:1px solid var(--border);
}

.empty-icon{
    font-size:60px;
    margin-bottom:15px;
}

.empty-title{
    font-size:24px;
    font-weight:700;
    margin-bottom:8px;
}
</style>
</head>
<body>
<aside class="sidebar">
  <div class="sidebar-logo"><div class="logo-icon">🔐</div><div class="logo-text">SecureVault <span class="logo-badge">ENC</span></div></div>
  <span class="nav-label">Vault Saya</span>
  <a href="index.php" class="nav-item"><span>🏠</span> Semua File</a>
  <a href="upload.php" class="nav-item"><span>⬆️</span> Upload File</a>
  <a href="shared.php" class="nav-item"><span>🔗</span> Dibagikan ke Saya</a>
  <a href="audit.php" class="nav-item active"><span>📋</span> Riwayat Aktivitas</a>
  <div class="sidebar-bottom"><div class="user-info">
    <div class="avatar"><?= strtoupper(substr($_SESSION['username'], 0, 1)) ?></div>
    <div><div class="user-name"><?= htmlspecialchars($_SESSION['username']) ?></div><div class="user-role">RSA-2048 Active</div></div>
    <a href="../auth/logout.php" class="logout-btn">⏏</a>
  </div></div>
</aside>

<div class="main">
  <div class="page-title">📋 Riwayat Aktivitas</div>
  <p class="page-sub">Log semua aktivitas kriptografi pada akun Anda</p>

  <?php if (empty($logs)): ?>
    <div class="empty-state">
      <div class="empty-icon">📋</div>
      <div class="empty-title">Belum Ada Aktivitas</div>
      <p>Aktivitas upload, download, dan share akan muncul di sini</p>
    </div>
  <?php else: ?>
    <div class="timeline">
      <?php foreach ($logs as $log):
        [$icon, $color] = activityIcon($log['aktivitas']);
      ?>
      <div class="tl-item">
        <div class="tl-icon" style="background: <?= $color ?>20; border: 2px solid <?= $color ?>40"><?= $icon ?></div>
        <div class="tl-body">
          <div class="tl-activity" style="color: <?= $color ?>"><?= htmlspecialchars($log['aktivitas']) ?></div>
          <div class="tl-file">📄 <?= htmlspecialchars($log['nama_file'] ?? '-') ?></div>
          <div class="tl-time">🕐 <?= date('d M Y, H:i:s', strtotime($log['created_at'])) ?></div>
        </div>
      </div>
      <?php endforeach; ?>
    </div>
  <?php endif; ?>
</div>
</body>
</html>
