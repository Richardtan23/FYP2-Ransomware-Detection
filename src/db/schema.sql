CREATE DATABASE IF NOT EXISTS ransomware_db;
USE ransomware_db;

CREATE TABLE IF NOT EXISTS detection_logs (
    id INT AUTO_INCREMENT PRIMARY KEY,
    filename VARCHAR(255),
    verdict VARCHAR(20),
    probability FLOAT,
    timestamp DATETIME
);
