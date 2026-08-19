<?php
// ===== API: LOGIN =====
// INI BAGIAN YANG SEBELUMNYA BERMASALAH: pastikan endpoint ini benar-benar
// mengecek ke tabel `users`, dan HANYA balas success:true kalau emailnya
// ketemu di database DAN password-nya cocok. Kalau tidak, balas
// success:false dengan pesan "belum terdaftar" supaya user diarahkan
// untuk daftar dulu (script.js sudah menangani ini lewat alert()).
header('Content-Type: application/json');
require 'db_connect.php';

$data = json_decode(file_get_contents('php://input'), true);

$email    = trim($data['email'] ?? '');
$password = $data['password'] ?? '';

if ($email === '' || $password === '') {
    echo json_encode(['success' => false, 'message' => 'Email dan password wajib diisi.']);
    exit;
}

// ----- Cari user berdasarkan email -----
$stmt = $conn->prepare('SELECT id, name, email, password FROM users WHERE email = ? LIMIT 1');
$stmt->bind_param('s', $email);
$stmt->execute();
$result = $stmt->get_result();

// ----- KUNCI PERBAIKANNYA DI SINI -----
// Kalau tidak ada baris yang cocok, akun ini memang belum pernah daftar.
// Jangan pernah return success:true untuk kasus ini.
if ($result->num_rows === 0) {
    echo json_encode([
        'success' => false,
        'message' => 'Akun dengan email ini belum terdaftar. Silakan daftar dahulu.',
    ]);
    $stmt->close();
    $conn->close();
    exit;
}

$user = $result->fetch_assoc();

// ----- Cocokkan password yang diketik dengan hash yang tersimpan -----
if (!password_verify($password, $user['password'])) {
    echo json_encode(['success' => false, 'message' => 'Password salah. Coba lagi.']);
    $stmt->close();
    $conn->close();
    exit;
}

// ----- Sukses: email ketemu DAN password cocok -----
echo json_encode([
    'success' => true,
    'name'    => $user['name'],
    'email'   => $user['email'],
]);

$stmt->close();
$conn->close();