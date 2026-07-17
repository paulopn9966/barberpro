@echo off
start "" /min "C:\xampp\mysql\bin\mysqld.exe" --defaults-file=C:\xampp\mysql\bin\my.ini --standalone
start "" /min "C:\xampp\apache\bin\httpd.exe"
timeout /t 3 /nobreak >nul
start "" "http://localhost/barbearia-system/"
