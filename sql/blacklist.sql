-- Sentinel AI: Blacklist Table
-- Run this in your MySQL database before starting the sentinel

CREATE TABLE IF NOT EXISTS blacklist (
    id INT AUTO_INCREMENT PRIMARY KEY,
    ip_address VARCHAR(45) NOT NULL,
    attack_type VARCHAR(255) NOT NULL,
    time_blocked TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);
