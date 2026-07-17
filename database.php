<?php
function db()
{
    static $p;
    if (!$p) {
        $p = new PDO(
            "mysql:host=localhost;dbname=barbearia_system;charset=utf8mb4",
            "root",
            "",
            [
                PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION,
                PDO::ATTR_DEFAULT_FETCH_MODE => PDO::FETCH_ASSOC,
            ],
        );
    }
    return $p;
}
