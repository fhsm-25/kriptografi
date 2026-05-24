-- ============================================================
-- SecureVault Database Schema (FIXED)
-- Perubahan dari versi lama:
--   1. Kolom `private_key` DIHAPUS dari tabel users
--   2. Kolom `private_key_encrypted` DITAMBAHKAN
--      (format: base64(salt)|base64(iv)|base64(ciphertext AES-CBC))
--      Private key dienkripsi dengan PBKDF2-SHA256 + AES-256-CBC
--      menggunakan password user — tidak pernah disimpan plaintext
--   3. Kolom `file_hash` DITAMBAHKAN ke tabel files
--      untuk verifikasi integritas SHA-256 saat download
--   4. INDEX pada shared_files untuk performa query
-- ============================================================

SET SQL_MODE = "NO_AUTO_VALUE_ON_ZERO";
START TRANSACTION;
SET time_zone = "+00:00";
SET NAMES utf8mb4;

CREATE DATABASE IF NOT EXISTS `securevault`
  DEFAULT CHARACTER SET utf8mb4
  COLLATE utf8mb4_general_ci;

USE `securevault`;

-- ============================================================
-- Tabel: users
-- private_key TIDAK disimpan plaintext
-- private_key_encrypted berisi: base64(salt)|base64(iv)|base64(AES-CBC(private_key))
-- ============================================================
CREATE TABLE IF NOT EXISTS `users` (
  `id`                    INT(11)      NOT NULL AUTO_INCREMENT,
  `username`              VARCHAR(100) NOT NULL,
  `password`              VARCHAR(255) NOT NULL COMMENT 'bcrypt hash',
  `public_key`            LONGTEXT     NOT NULL COMMENT 'RSA public key PEM',
  `private_key_encrypted` LONGTEXT     NOT NULL COMMENT 'PBKDF2+AES-CBC encrypted private key',
  `created_at`            TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  UNIQUE KEY `username` (`username`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================
-- Tabel: files
-- file_hash untuk verifikasi integritas SHA-256
-- ============================================================
CREATE TABLE IF NOT EXISTS `files` (
  `id`                INT(11)      NOT NULL AUTO_INCREMENT,
  `user_id`           INT(11)      NOT NULL,
  `original_name`     VARCHAR(255) NOT NULL,
  `encrypted_name`    VARCHAR(255) NOT NULL,
  `encrypted_aes_key` LONGTEXT     NOT NULL COMMENT 'RSA-OAEP wrapped AES key',
  `iv`                TEXT         NOT NULL COMMENT 'base64 encoded 96-bit GCM IV',
  `auth_tag`          TEXT         NOT NULL COMMENT 'base64 encoded 128-bit GCM auth tag',
  `file_hash`         VARCHAR(64)  DEFAULT NULL COMMENT 'SHA-256 hash of plaintext file',
  `created_at`        TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `user_id` (`user_id`),
  CONSTRAINT `files_ibfk_1` FOREIGN KEY (`user_id`) REFERENCES `users` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================
-- Tabel: shared_files
-- encrypted_aes_key di sini berbeda dengan di files —
-- ini adalah AES key yang sudah di-wrap ulang (key wrapping)
-- dengan public key penerima (shared_to)
-- ============================================================
CREATE TABLE IF NOT EXISTS `shared_files` (
  `id`                INT(11)   NOT NULL AUTO_INCREMENT,
  `file_id`           INT(11)   NOT NULL,
  `owner_id`          INT(11)   NOT NULL,
  `shared_to`         INT(11)   NOT NULL,
  `encrypted_aes_key` LONGTEXT  NOT NULL COMMENT 'AES key wrapped dengan public key penerima (RSA-OAEP)',
  `shared_at`         TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_shared_to`  (`shared_to`),
  KEY `idx_file_owner` (`file_id`, `owner_id`),
  CONSTRAINT `shared_files_ibfk_1` FOREIGN KEY (`file_id`) REFERENCES `files` (`id`) ON DELETE CASCADE
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

-- ============================================================
-- Tabel: audit_logs
-- ============================================================
CREATE TABLE IF NOT EXISTS `audit_logs` (
  `id`         INT(11)      NOT NULL AUTO_INCREMENT,
  `user_id`    INT(11)      NOT NULL,
  `aktivitas`  VARCHAR(100) DEFAULT NULL,
  `nama_file`  VARCHAR(255) DEFAULT NULL,
  `created_at` TIMESTAMP    NOT NULL DEFAULT CURRENT_TIMESTAMP,
  PRIMARY KEY (`id`),
  KEY `idx_user_id` (`user_id`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_general_ci;

COMMIT;

-- ============================================================
-- CATATAN MIGRASI (jika upgrade dari versi lama):
--
-- ALTER TABLE users
--   ADD COLUMN private_key_encrypted LONGTEXT NOT NULL AFTER public_key;
--
-- ALTER TABLE files
--   ADD COLUMN file_hash VARCHAR(64) DEFAULT NULL AFTER auth_tag;
--
-- Setelah migrasi data, jalankan:
-- ALTER TABLE users DROP COLUMN private_key;
--
-- PENTING: User lama harus register ulang karena private key
-- versi lama tidak bisa di-enkripsi retroaktif tanpa password user.
-- ============================================================
