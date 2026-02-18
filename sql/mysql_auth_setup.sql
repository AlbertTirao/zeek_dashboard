-- MySQL auth setup for Zeek Dashboard
-- Run this once on your MySQL server.

CREATE DATABASE IF NOT EXISTS zeek_dashboard
  CHARACTER SET utf8mb4
  COLLATE utf8mb4_unicode_ci;

USE zeek_dashboard;

CREATE TABLE IF NOT EXISTS auth_users (
  id BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
  username VARCHAR(64) NOT NULL,
  password_hash VARCHAR(255) NOT NULL,
  role ENUM('admin', 'staff') NOT NULL DEFAULT 'staff',
  is_active TINYINT(1) NOT NULL DEFAULT 1,
  created_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
  updated_at TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,
  PRIMARY KEY (id),
  UNIQUE KEY uq_auth_users_username (username)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4;

-- Demo users (change password hashes in production)
-- admin / admin123
-- staff / staff123
INSERT INTO auth_users (username, password_hash, role, is_active)
VALUES
  ('admin', 'pbkdf2_sha256$200000$sr2XiZggR9IxkWE654fxWA==$7jQF18ZQaIKBKqdZZmR3OUo6XstaVCGRh6He2LAecDE=', 'admin', 1),
  ('staff', 'pbkdf2_sha256$200000$sYf4Nf0L5KGaN3BhGBF56g==$tGbWq6wjub0TF5eYOmORQvlLj2Eg2b8iNJvTt7VOL4g=', 'staff', 1)
ON DUPLICATE KEY UPDATE
  password_hash = VALUES(password_hash),
  role = VALUES(role),
  is_active = VALUES(is_active);
