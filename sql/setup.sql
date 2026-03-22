-- Sentinel AI — Test Database Setup
-- Run this in phpMyAdmin before using target.php
-- 
-- Instructions:
-- 1. Open phpMyAdmin (http://localhost/phpmyadmin)
-- 2. Click "New" to create a new database
-- 3. Name it: sentinel_test
-- 4. Click the SQL tab
-- 5. Paste and run this entire file

CREATE DATABASE IF NOT EXISTS sentinel_test;
USE sentinel_test;

-- Bookings table (the vulnerable target)
CREATE TABLE IF NOT EXISTS bookings (
    id          INT AUTO_INCREMENT PRIMARY KEY,
    location    VARCHAR(255),
    guests      INT,
    event_date  DATE,
    ip_address  VARCHAR(45),
    created_at  TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Blacklist table (managed by Sentinel AI Python sentinel)
CREATE TABLE IF NOT EXISTS blacklist (
    id           INT AUTO_INCREMENT PRIMARY KEY,
    ip_address   VARCHAR(45) NOT NULL,
    attack_type  VARCHAR(255) NOT NULL,
    time_blocked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

-- Confirm setup
SELECT 'Setup complete! Tables created: bookings, blacklist' AS status;
