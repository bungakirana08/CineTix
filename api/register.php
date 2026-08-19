<?php
// ===== API: DAFTAR AKUN BARU =====
header('Content-Type: application/json');
require 'db_connect.php';

$data = json_decode(file_get_contents('php://input'), true);

$name     = trim($data['name'] ?? '');
$email    = trim($data['email'] ?? '');
$password = $data['password'] ?? '';

// ----- Validasi input -----
if ($name === '' || $email === '' || $password === '') {
    echo json_encode(['success' => false, 'message' => 'Nama, email, dan password wajib diisi.']);
    exit;
}
if (!filter_var($email, FILTER_VALIDATE_EMAIL)) {
    echo json_encode(['success' => false, 'message' => 'Format email tidak valid.']);
    exit;
}
if (strlen($password) < 6) {
    echo json_encode(['success' => false, 'message' => 'Password minimal 6 karakter.']);
    exit;
}

// ----- Cek apakah email SUDAH terdaftar -----
$stmt = $conn->prepare('SELECT id FROM users WHERE email = ? LIMIT 1');
$stmt->bind_param('s', $email);
$stmt->execute();
$stmt->store_result();

if ($stmt->num_rows > 0) {
    echo json_encode(['success' => false, 'message' => 'Email ini sudah terdaftar. Silakan masuk (Sign In).']);
    $stmt->close();
    $conn->close();
    exit;
}
$stmt->close();

// ----- Simpan akun baru (password di-hash, TIDAK disimpan plain text) -----
$hashedPassword = password_hash($password, PASSWORD_DEFAULT);

$provider = 'email';
$stmt = $conn->prepare('INSERT INTO users (name, email, password, provider) VALUES (?, ?, ?, ?)');
$stmt->bind_param('ssss', $name, $email, $hashedPassword, $provider);

if ($stmt->execute()) {
    echo json_encode([
        'success' => true,
        'name'    => $name,
        'email'   => $email,
    ]);
} else {
    echo json_encode(['success' => false, 'message' => 'Gagal menyimpan akun. Coba lagi.']);
}

$stmt->close();
$conn->close();