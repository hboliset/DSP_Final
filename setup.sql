DROP DATABASE IF EXISTS dsp_db;
CREATE DATABASE dsp_db;
USE dsp_db;

CREATE TABLE health_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    first_name VARCHAR(255),
    last_name VARCHAR(255),
    gender BOOLEAN,
    age INT,
    weight DECIMAL(5,2),  
    height DECIMAL(5,2),
    health_history TEXT,
    data_hash VARCHAR(64) 
);

CREATE TABLE users_info (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(255) UNIQUE,
    password_hash VARCHAR(255),
    role ENUM('H', 'R') NOT NULL
);
