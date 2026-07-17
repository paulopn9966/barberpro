CREATE DATABASE IF NOT EXISTS barbearia_system CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci; USE barbearia_system;
CREATE TABLE roles(id INT AUTO_INCREMENT PRIMARY KEY,name VARCHAR(60) UNIQUE,permissions TEXT,active TINYINT DEFAULT 1);
CREATE TABLE users(id INT AUTO_INCREMENT PRIMARY KEY,name VARCHAR(120),email VARCHAR(150) UNIQUE,password VARCHAR(255),role_id INT,active TINYINT DEFAULT 1,last_seen_appointment_id INT DEFAULT 0,FOREIGN KEY(role_id) REFERENCES roles(id));
CREATE TABLE clients(id INT AUTO_INCREMENT PRIMARY KEY,name VARCHAR(150),phone VARCHAR(30),email VARCHAR(150),notes TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
CREATE TABLE services(id INT AUTO_INCREMENT PRIMARY KEY,name VARCHAR(120),price DECIMAL(10,2),duration INT,active TINYINT DEFAULT 1);
CREATE TABLE appointments(id INT AUTO_INCREMENT PRIMARY KEY,client_id INT,service_id INT,start_at DATETIME,status VARCHAR(30),notes TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(client_id) REFERENCES clients(id),FOREIGN KEY(service_id) REFERENCES services(id));
CREATE TABLE finance(id INT AUTO_INCREMENT PRIMARY KEY,type VARCHAR(20),description VARCHAR(180),amount DECIMAL(10,2),date DATE,status VARCHAR(20),payment_method VARCHAR(30) DEFAULT 'Dinheiro');
INSERT INTO roles(name,permissions) VALUES
('Administrador','all'),
('Gerente','clients.view,clients.manage,history.view,appointments.view,appointments.manage,services.view,services.manage,barbers.view,barbers.manage,inventory.view,inventory.manage,reports.view,reports.export'),
('Barbeiro','clients.view,clients.manage,history.view,appointments.view,appointments.manage,services.view,barbers.view'),
('Recepção','clients.view,clients.manage,history.view,appointments.view,appointments.manage,services.view,barbers.view,inventory.view');
INSERT INTO users(name,email,password,role_id) VALUES('Administrador','admin',SHA2('admin123',256),1);
INSERT INTO services(name,price,duration) VALUES('Corte masculino',35,40),('Barba',25,25),('Corte + Barba',55,60);
CREATE TABLE barbers(id INT AUTO_INCREMENT PRIMARY KEY,name VARCHAR(120) NOT NULL,phone VARCHAR(30),commission_pct DECIMAL(5,2) DEFAULT 0,active TINYINT DEFAULT 1,user_id INT NULL UNIQUE,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL);
INSERT INTO barbers(name,active) VALUES('Profissional principal',1);
ALTER TABLE appointments ADD barber_id INT NULL AFTER service_id, ADD finance_created TINYINT DEFAULT 0, ADD FOREIGN KEY(barber_id) REFERENCES barbers(id);
ALTER TABLE finance ADD appointment_id INT NULL, ADD UNIQUE KEY unique_appointment_finance(appointment_id);
CREATE TABLE settings(setting_key VARCHAR(80) PRIMARY KEY,setting_value TEXT);
INSERT INTO settings(setting_key,setting_value) VALUES
('business_name','BarberPro'),('phone',''),('address',''),('logo',''),('open_time','08:00'),('close_time','19:00'),('lunch_start','12:00'),('lunch_end','13:00'),('work_days','1,2,3,4,5,6');
CREATE TABLE audit_logs(id BIGINT AUTO_INCREMENT PRIMARY KEY,user_id INT NULL,action VARCHAR(120),details TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL);
CREATE TABLE notification_reads(user_id INT NOT NULL,appointment_id INT NOT NULL,read_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,PRIMARY KEY(user_id,appointment_id),FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE CASCADE,FOREIGN KEY(appointment_id) REFERENCES appointments(id) ON DELETE CASCADE);
CREATE TABLE barber_blocks(id INT AUTO_INCREMENT PRIMARY KEY,barber_id INT NOT NULL,start_at DATETIME NOT NULL,end_at DATETIME NOT NULL,reason VARCHAR(160),created_by INT NULL,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(barber_id) REFERENCES barbers(id) ON DELETE CASCADE,FOREIGN KEY(created_by) REFERENCES users(id) ON DELETE SET NULL);
CREATE TABLE appointment_history(id BIGINT AUTO_INCREMENT PRIMARY KEY,appointment_id INT NOT NULL,user_id INT NULL,action VARCHAR(80) NOT NULL,details TEXT,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(appointment_id) REFERENCES appointments(id) ON DELETE CASCADE,FOREIGN KEY(user_id) REFERENCES users(id) ON DELETE SET NULL);
CREATE TABLE waitlist(id INT AUTO_INCREMENT PRIMARY KEY,name VARCHAR(150) NOT NULL,phone VARCHAR(30) NOT NULL,service_id INT NULL,barber_id INT NULL,preferred_date DATE NULL,notes VARCHAR(255),status VARCHAR(30) DEFAULT 'Aguardando',created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,FOREIGN KEY(service_id) REFERENCES services(id) ON DELETE SET NULL,FOREIGN KEY(barber_id) REFERENCES barbers(id) ON DELETE SET NULL);
CREATE TABLE inventory(id INT AUTO_INCREMENT PRIMARY KEY,name VARCHAR(140) NOT NULL,category VARCHAR(80),stock DECIMAL(10,2) DEFAULT 0,min_stock DECIMAL(10,2) DEFAULT 0,unit VARCHAR(20) DEFAULT 'un',cost DECIMAL(10,2) DEFAULT 0,price DECIMAL(10,2) DEFAULT 0,active TINYINT DEFAULT 1,created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP);
INSERT INTO settings(setting_key,setting_value) VALUES
('public_booking_enabled','1'),('booking_interval','30'),('booking_notice','Seu horário será confirmado pela barbearia.'),('backup_last_month','')
,
('admin_recovery_hash','')
ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value);
