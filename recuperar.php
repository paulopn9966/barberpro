<?php
declare(strict_types=1);
session_start();
require __DIR__ . "/database.php";
function e($v)
{
    return htmlspecialchars((string) $v, ENT_QUOTES, "UTF-8");
}
function token()
{
    return $_SESSION["recovery_csrf"] ??= bin2hex(random_bytes(32));
}
$error = "";
$success = false;
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    if (!hash_equals($_SESSION["recovery_csrf"] ?? "", $_POST["csrf"] ?? "")) {
        $error = "A página expirou. Atualize e tente novamente.";
    } elseif (
        isset($_SESSION["recovery_attempt"]) &&
        time() - $_SESSION["recovery_attempt"] < 5
    ) {
        $error = "Aguarde alguns segundos antes de tentar novamente.";
    } else {
        $_SESSION["recovery_attempt"] = time();
        $s = db()->prepare(
            "SELECT u.id FROM users u JOIN roles r ON r.id=u.role_id WHERE u.email=? AND r.name='Administrador'",
        );
        $s->execute([trim($_POST["username"] ?? "")]);
        $id = (int) $s->fetchColumn();
        $hash = db()
            ->query(
                "SELECT setting_value FROM settings WHERE setting_key='admin_recovery_hash'",
            )
            ->fetchColumn();
        if (
            !$id ||
            !$hash ||
            !password_verify(trim($_POST["recovery_code"] ?? ""), $hash)
        ) {
            $error = "Login ou código de recuperação inválido.";
        } elseif (
            strlen($_POST["new_password"] ?? "") < 8 ||
            $_POST["new_password"] !== $_POST["confirm_password"]
        ) {
            $error =
                "A nova senha precisa ter 8 caracteres e a confirmação deve ser igual.";
        } else {
            $s = db()->prepare(
                "UPDATE users SET password=?,active=1 WHERE id=?",
            );
            $s->execute([
                password_hash($_POST["new_password"], PASSWORD_DEFAULT),
                $id,
            ]);
            $success = true;
        }
    }
}
?><!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><title>Recuperar acesso | BarberPro</title><link rel="stylesheet" href="booking.css"></head><body><main class="booking-shell"><section class="booking-brand"><div class="public-logo">✂</div><small>RECUPERAÇÃO SEGURA</small><h1>BarberPro</h1><p>Use o código de recuperação definido anteriormente pelo administrador.</p></section><section class="booking-card"><?php if (
    $success
): ?><div class="booking-success"><div>✓</div><h2>Senha redefinida</h2><p>Seu acesso administrativo foi reativado.</p><a href="index.php">Voltar ao login</a></div><?php else: ?><div class="booking-head"><span>ADMINISTRADOR</span><h2>Recuperar acesso</h2></div><?php if (
    $error
): ?><div class="booking-error"><?= e(
    $error,
) ?></div><?php endif; ?><form method="post"><input type="hidden" name="csrf" value="<?= token() ?>"><label>Login do administrador</label><input name="username" required><label>Código de recuperação</label><input name="recovery_code" type="password" required><label>Nova senha</label><input name="new_password" type="password" minlength="8" required><label>Confirmar nova senha</label><input name="confirm_password" type="password" minlength="8" required><button>Redefinir acesso</button><small class="booking-note">Sem o código, a senha não poderá ser alterada.</small></form><?php endif; ?></section></main></body></html>
