CREATE DATABASE IF NOT EXISTS security_bmi_lab
    CHARACTER SET utf8mb4
    COLLATE utf8mb4_unicode_ci;

USE security_bmi_lab;

DROP TABLE IF EXISTS persons;
DROP TABLE IF EXISTS users;

CREATE TABLE users (
    id            INT AUTO_INCREMENT PRIMARY KEY,
    name          VARCHAR(100)  NOT NULL,
    email         VARCHAR(100)  NOT NULL UNIQUE,
    password_hash VARCHAR(255)  NOT NULL,         
    role          ENUM('user', 'staff', 'admin')
                  NOT NULL DEFAULT 'user',         
    created_at    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);


CREATE TABLE persons (
    id         INT AUTO_INCREMENT PRIMARY KEY,
    user_id    INT            NOT NULL,
    name       VARCHAR(100)   NOT NULL,
    age        INT            NOT NULL,
    height     DECIMAL(5,2)   NOT NULL,           
    weight     DECIMAL(5,2)   NOT NULL,            
    bmi        DECIMAL(5,2)   NOT NULL,           
    category   VARCHAR(30)    NOT NULL,            
    notes      TEXT           NULL,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE
);