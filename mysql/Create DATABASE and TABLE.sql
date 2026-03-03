CREATE DATABASE IF NOT EXISTS zeek_auth
  CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;

CREATE USER IF NOT EXISTS 'zeek_auth_user'@'%' IDENTIFIED BY 'StrongPass!123';
GRANT ALL PRIVILEGES ON zeek_auth.* TO 'zeek_auth_user'@'%';
FLUSH PRIVILEGES;
