<?php
ini_set("session.use_strict_mode", "1");
session_set_cookie_params(["httponly" => true, "samesite" => "Lax"]);
session_start();
require __DIR__ . "/database.php";
header("X-Content-Type-Options: nosniff");
header("X-Frame-Options: SAMEORIGIN");
header("Referrer-Policy: strict-origin-when-cross-origin");
if (
    isset($_SESSION["last_activity"]) &&
    time() - $_SESSION["last_activity"] > 28800
) {
    session_unset();
    session_destroy();
    header("Location:index.php?expired=1");
    exit();
}
$_SESSION["last_activity"] = time();
function e($v)
{
    return htmlspecialchars((string) $v, ENT_QUOTES, "UTF-8");
}
function money($v)
{
    return 'R$ ' . number_format((float) $v, 2, ",", ".");
}
function current_file()
{
    return basename($_SERVER["PHP_SELF"]);
}
function back()
{
    header("Location:" . current_file());
    exit();
}
function setting($key, $default = "")
{
    $s = db()->prepare(
        "SELECT setting_value FROM settings WHERE setting_key=?",
    );
    $s->execute([$key]);
    return $s->fetchColumn() ?: $default;
}
function audit($action, $details = "")
{
    try {
        $s = db()->prepare(
            "INSERT INTO audit_logs(user_id,action,details) VALUES(?,?,?)",
        );
        $s->execute([$_SESSION["user"]["id"] ?? null, $action, $details]);
    } catch (Throwable) {
    }
}
function csrf_token()
{
    return $_SESSION["csrf"] ??= bin2hex(random_bytes(32));
}
function verify_csrf($token)
{
    if (!hash_equals($_SESSION["csrf"] ?? "", (string) $token)) {
        http_response_code(419);
        exit("Sessão expirada. Atualize a página e tente novamente.");
    }
}
function current_password_ok($password)
{
    $s = db()->prepare("SELECT password FROM users WHERE id=?");
    $s->execute([$_SESSION["user"]["id"]]);
    $hash = $s->fetchColumn();
    return password_verify($password, $hash) ||
        hash("sha256", $password) === $hash;
}
function permission_chips($csv)
{
    if ($csv === "all") {
        return '<span class="perm-chip total">Acesso total</span>';
    }
    $labels = [
        "clients.view" => "Clientes",
        "clients.manage" => "Editar clientes",
        "history.view" => "Histórico",
        "appointments.view" => "Agenda",
        "appointments.manage" => "Editar agenda",
        "services.view" => "Serviços",
        "services.manage" => "Editar serviços",
        "barbers.view" => "Barbeiros",
        "barbers.manage" => "Editar barbeiros",
        "inventory.view" => "Estoque",
        "inventory.manage" => "Editar estoque",
        "reports.view" => "Relatórios",
        "reports.export" => "Exportar relatórios",
        "users.view" => "Logins",
        "users.manage" => "Editar logins",
        "roles.view" => "Funções",
        "roles.manage" => "Editar funções",
        "backups.view" => "Backup",
        "backups.manage" => "Restaurar backup",
        "settings.view" => "Configurações",
        "settings.manage" => "Editar configurações",
    ];
    $html = "";
    foreach (array_filter(explode(",", $csv)) as $key) {
        $html .=
            '<span class="perm-chip">' . e($labels[$key] ?? $key) . "</span>";
    }
    return $html ?: '<span class="perm-chip muted">Sem permissões</span>';
}
function has_perm($permission)
{
    if (
        ($_SESSION["user"]["role"] ?? "") === "Administrador" ||
        ($_SESSION["user"]["permissions"] ?? "") === "all"
    ) {
        return true;
    }
    $permissions = explode(",", $_SESSION["user"]["permissions"] ?? "");
    if (in_array($permission, $permissions, true)) {
        return true;
    }
    $module = explode(".", $permission)[0];
    return in_array($module, $permissions, true);
}
function require_perm($permission)
{
    if (!has_perm($permission)) {
        http_response_code(403);
        exit(
            "Você pode visualizar esta área, mas não tem permissão para realizar esta alteração."
        );
    }
}
if (isset($_GET["logout"])) {
    session_destroy();
    header("Location:index.php");
    exit();
}
if (!isset($_SESSION["user"])) {

    $error = "";
    $errorType = "";
    if ($_POST) {
        $s = db()->prepare(
            "SELECT u.*,u.active user_active,r.name role,r.permissions,r.active role_active FROM users u JOIN roles r ON r.id=u.role_id WHERE email=?",
        );
        $s->execute([trim($_POST["username"])]);
        $u = $s->fetch();
        $passwordOk =
            $u &&
            (password_verify($_POST["password"], $u["password"]) ||
                hash("sha256", $_POST["password"]) === $u["password"]);
        if ($passwordOk && !$u["user_active"]) {
            $error = "Este usuário está desativado.";
            $errorType = "disabled";
        } elseif ($passwordOk && !$u["role_active"]) {
            $error = "O cargo deste usuário está desativado.";
            $errorType = "disabled";
        } elseif ($passwordOk) {
            if (strlen($u["password"]) === 64) {
                $hash = password_hash($_POST["password"], PASSWORD_DEFAULT);
                db()
                    ->prepare("UPDATE users SET password=? WHERE id=?")
                    ->execute([$hash, $u["id"]]);
                $u["password"] = $hash;
            }
            if (isset($_POST["remember"])) {
                setcookie("remembered_login", trim($_POST["username"]), [
                    "expires" => time() + 2592000,
                    "path" => "/",
                    "httponly" => true,
                    "samesite" => "Lax",
                ]);
            } else {
                setcookie("remembered_login", "", [
                    "expires" => time() - 3600,
                    "path" => "/",
                    "httponly" => true,
                    "samesite" => "Lax",
                ]);
            }
            session_regenerate_id(true);
            $_SESSION["user"] = $u;
            $_SESSION["last_activity"] = time();
            audit("Login", "Entrada no sistema");
            header("Location:index.php");
            exit();
        } else {
            $error = "Login ou senha inválidos.";
            $errorType = "error";
        }
    }
    ?><!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><link rel="stylesheet" href="style.css"><link rel="stylesheet" href="professional.css"><title>Entrar | BarberPro</title></head><body class="login"><form method="post" class="loginbox"><div class="logo"><span class="logo-mark">✂</span><span>BARBER<b>PRO</b></span></div><h1>Bem-vindo</h1><p>Entre para gerenciar sua barbearia</p><?php if (
    $error
): ?><div class="login-alert <?= e(
    $errorType,
) ?>"><span class="login-alert-icon"><?= $errorType === "disabled"
    ? "!"
    : "×" ?></span><div><b><?= $errorType === "disabled"
    ? "Acesso bloqueado"
    : "Não foi possível entrar" ?></b><p><?= e($error) ?></p><?php if (
    $errorType === "disabled"
): ?><small>Entre em contato com o administrador da barbearia para reativar seu acesso.</small><?php endif; ?></div></div><?php endif; ?><label>Login</label><input type="text" name="username" autocomplete="username" placeholder="Digite seu login" value="<?= e(
    $_COOKIE["remembered_login"] ?? "",
) ?>" required><label>Senha</label><input type="password" name="password" required><label class="remember-login"><input type="checkbox" name="remember" value="1" <?= isset(
    $_COOKIE["remembered_login"],
)
    ? "checked"
    : "" ?>><span><b>Lembrar meu login</b><small>Preenche apenas o nome do usuário neste computador.</small></span></label><button>ENTRAR</button><small>Digite o login e a senha cadastrados pelo administrador.</small><a class="forgot-link" href="recuperar.php">Esqueci meu acesso administrativo</a></form></body></html><?php exit();
}
if ($_SERVER["REQUEST_METHOD"] === "POST") {
    verify_csrf($_POST["csrf"] ?? "");
}
$files = [
    "dashboard" => "index.php",
    "clients" => "clientes.php",
    "history" => "historico.php",
    "appointments" => "agenda.php",
    "weekly" => "agenda_semanal.php",
    "blocks" => "bloqueios.php",
    "waitlist" => "lista_espera.php",
    "services" => "servicos.php",
    "barbers" => "barbeiros.php",
    "inventory" => "estoque.php",
    "reports" => "relatorios.php",
    "profile" => "perfil.php",
    "users" => "logins.php",
    "roles" => "funcoes.php",
    "security" => "seguranca.php",
    "backups" => "backup.php",
    "settings" => "configuracoes.php",
];
$titles = [
    "dashboard" => "Painel",
    "clients" => "Clientes",
    "history" => "Histórico",
    "appointments" => "Agenda",
    "weekly" => "Agenda semanal",
    "blocks" => "Folgas e bloqueios",
    "waitlist" => "Lista de espera",
    "services" => "Serviços",
    "barbers" => "Barbeiros",
    "inventory" => "Estoque",
    "reports" => "Relatórios",
    "profile" => "Meu perfil",
    "users" => "Logins",
    "roles" => "Funções",
    "security" => "Segurança",
    "backups" => "Backup",
    "settings" => "Configurações",
];
$tables = [
    "clients" => "clients",
    "appointments" => "appointments",
    "services" => "services",
    "barbers" => "barbers",
    "inventory" => "inventory",
    "users" => "users",
    "roles" => "roles",
];
$permissionModule = in_array($module, ["weekly", "blocks", "waitlist"], true)
    ? "appointments"
    : $module;
$allowed =
    in_array($module, ["dashboard", "security", "profile"], true) ||
    has_perm($permissionModule . ".view");
$canManage =
    in_array($module, ["dashboard", "security", "profile"], true) ||
    has_perm($permissionModule . ".manage");
if (
    $module === "users" &&
    ($_SESSION["user"]["role"] ?? "") !== "Administrador"
) {
    $allowed = false;
    $canManage = false;
}
if (!$allowed) {
    http_response_code(403);
    exit("Você não tem permissão para acessar esta área.");
}
if ($module === "appointments" && isset($_GET["confirm"])) {
    verify_csrf($_GET["csrf"] ?? "");
    require_perm("appointments.manage");
    $s = db()->prepare(
        "SELECT a.id,a.start_at,c.name client,c.phone,s.name service,b.name barber FROM appointments a JOIN clients c ON c.id=a.client_id JOIN services s ON s.id=a.service_id LEFT JOIN barbers b ON b.id=a.barber_id WHERE a.id=?",
    );
    $s->execute([(int) $_GET["confirm"]]);
    $ap = $s->fetch();
    if ($ap) {
        db()
            ->prepare("UPDATE appointments SET status='Confirmado' WHERE id=?")
            ->execute([$ap["id"]]);
        db()
            ->prepare(
                "INSERT INTO appointment_history(appointment_id,user_id,action,details) VALUES(?,?,'Confirmado','Cliente avisado pelo WhatsApp')",
            )
            ->execute([$ap["id"], $_SESSION["user"]["id"]]);
        audit("Agendamento confirmado", "Agendamento #" . $ap["id"]);
        $text =
            "Olá " .
            $ap["client"] .
            "! Seu agendamento foi confirmado ✅" .
            "\n\n" .
            "Serviço: " .
            $ap["service"] .
            "\n" .
            "Profissional: " .
            ($ap["barber"] ?: "A definir") .
            "\n" .
            "Data: " .
            date("d/m/Y", strtotime($ap["start_at"])) .
            "\n" .
            "Horário: " .
            date("H:i", strtotime($ap["start_at"])) .
            "\n\n" .
            "Aguardamos você!";
        header(
            "Location:https://wa.me/55" .
                preg_replace("/\D/", "", $ap["phone"]) .
                "?text=" .
                urlencode($text),
        );
        exit();
    }
    $_SESSION["msg"] = "Agendamento não encontrado.";
    back();
}
if ($module === "settings" && $_POST) {
    require_perm("settings.manage");
    require_perm("settings.manage");
    require_perm("settings.manage");
    foreach (
        [
            "business_name",
            "phone",
            "address",
            "open_time",
            "close_time",
            "lunch_start",
            "lunch_end",
            "booking_interval",
            "booking_notice",
        ]
        as $key
    ) {
        $s = db()->prepare(
            "INSERT INTO settings(setting_key,setting_value) VALUES(?,?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)",
        );
        $s->execute([$key, trim($_POST[$key] ?? "")]);
    }
    $days = implode(",", $_POST["work_days"] ?? []);
    db()
        ->prepare(
            "INSERT INTO settings VALUES(?,?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)",
        )
        ->execute(["work_days", $days]);
    db()
        ->prepare(
            "INSERT INTO settings VALUES(?,?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)",
        )
        ->execute([
            "public_booking_enabled",
            isset($_POST["public_booking_enabled"]) ? "1" : "0",
        ]);
    audit("Configurações atualizadas");
    $_SESSION["msg"] = "Configurações salvas.";
    back();
}
if ($module === "blocks" && $_POST) {
    require_perm("appointments.manage");
    $start = $_POST["start_date"] . " " . $_POST["start_time"] . ":00";
    $end = $_POST["end_date"] . " " . $_POST["end_time"] . ":00";
    if (strtotime($end) <= strtotime($start)) {
        $_SESSION["msg"] = "O fim precisa ser depois do início.";
    } else {
        $q = db()->prepare(
            "INSERT INTO barber_blocks(barber_id,start_at,end_at,reason,created_by) VALUES(?,?,?,?,?)",
        );
        $q->execute([
            (int) $_POST["barber_id"],
            $start,
            $end,
            trim($_POST["reason"]),
            $_SESSION["user"]["id"],
        ]);
        audit("Horário bloqueado", trim($_POST["reason"]));
        $_SESSION["msg"] = "Folga ou horário bloqueado.";
    }
    back();
}
if ($module === "blocks" && isset($_GET["remove_block"])) {
    verify_csrf($_GET["csrf"] ?? "");
    require_perm("appointments.manage");
    db()
        ->prepare("DELETE FROM barber_blocks WHERE id=?")
        ->execute([(int) $_GET["remove_block"]]);
    $_SESSION["msg"] = "Bloqueio removido.";
    back();
}
if ($module === "waitlist" && isset($_GET["served"])) {
    verify_csrf($_GET["csrf"] ?? "");
    require_perm("appointments.manage");
    db()
        ->prepare("UPDATE waitlist SET status='Avisado' WHERE id=?")
        ->execute([(int) $_GET["served"]]);
    $_SESSION["msg"] = "Cliente marcado como avisado.";
    back();
}
if ($module === "waitlist" && isset($_GET["remove_wait"])) {
    verify_csrf($_GET["csrf"] ?? "");
    require_perm("appointments.manage");
    db()
        ->prepare("DELETE FROM waitlist WHERE id=?")
        ->execute([(int) $_GET["remove_wait"]]);
    $_SESSION["msg"] = "Cliente removido da lista.";
    back();
}
if ($module === "security" && $_POST) {
    if (($_POST["action"] ?? "password") === "recovery") {
        if (
            ($_SESSION["user"]["role"] ?? "") !== "Administrador" ||
            !current_password_ok($_POST["current_password"] ?? "") ||
            strlen(trim($_POST["recovery_code"] ?? "")) < 10
        ) {
            $_SESSION["msg"] = "Senha atual incorreta ou código muito curto.";
        } else {
            $hash = password_hash(
                trim($_POST["recovery_code"]),
                PASSWORD_DEFAULT,
            );
            db()
                ->prepare(
                    "INSERT INTO settings(setting_key,setting_value) VALUES('admin_recovery_hash',?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)",
                )
                ->execute([$hash]);
            audit("Código de recuperação alterado");
            $_SESSION["msg"] =
                "Código de recuperação salvo. Guarde-o em local seguro.";
        }
        back();
    }
    $s = db()->prepare("SELECT password FROM users WHERE id=?");
    $s->execute([$_SESSION["user"]["id"]]);
    $old = $s->fetchColumn();
    if (
        (password_verify($_POST["current_password"], $old) ||
            hash("sha256", $_POST["current_password"]) === $old) &&
        strlen($_POST["new_password"]) >= 8 &&
        $_POST["new_password"] === $_POST["confirm_password"]
    ) {
        db()
            ->prepare("UPDATE users SET password=? WHERE id=?")
            ->execute([
                password_hash($_POST["new_password"], PASSWORD_DEFAULT),
                $_SESSION["user"]["id"],
            ]);
        audit("Senha alterada");
        $_SESSION["msg"] = "Senha alterada com segurança.";
    } else {
        $_SESSION["msg"] = "Senha atual incorreta ou nova senha inválida.";
    }
    back();
}
if ($module === "backups" && isset($_GET["download"])) {
    require_perm("backups.view");
    $tablesBackup = [
        "roles",
        "users",
        "clients",
        "services",
        "barbers",
        "inventory",
        "appointments",
        "finance",
        "settings",
        "audit_logs",
    ];
    $sql = "SET FOREIGN_KEY_CHECKS=0;\n";
    foreach ($tablesBackup as $tb) {
        $create = db()
            ->query("SHOW CREATE TABLE `$tb`")
            ->fetch();
        $sql .=
            "DROP TABLE IF EXISTS `$tb`;\n" . $create["Create Table"] . ";\n";
        foreach (db()->query("SELECT * FROM `$tb`") as $row) {
            $vals = array_map(
                fn($v) => $v === null ? "NULL" : db()->quote((string) $v),
                array_values($row),
            );
            $sql .= "INSERT INTO `$tb` VALUES(" . implode(",", $vals) . ");\n";
        }
    }
    $sql .= "SET FOREIGN_KEY_CHECKS=1;\n";
    audit("Backup baixado");
    header("Content-Type: application/sql");
    header(
        "Content-Disposition: attachment; filename=barberpro-backup-" .
            date("Y-m-d-His") .
            ".sql",
    );
    echo $sql;
    exit();
}
if ($module === "backups" && $_POST && isset($_FILES["backup"])) {
    require_perm("backups.manage");
    if (
        ($_SESSION["user"]["role"] ?? "") !== "Administrador" ||
        !current_password_ok($_POST["confirm_password"] ?? "")
    ) {
        $_SESSION["msg"] =
            "Confirme a senha correta do administrador para restaurar.";
        back();
    }
    try {
        $sql = file_get_contents($_FILES["backup"]["tmp_name"]);
        if (strlen($sql) > 10000000) {
            throw new Exception();
        }
        db()->exec($sql);
        audit("Backup restaurado");
        $_SESSION["msg"] = "Backup restaurado com sucesso.";
    } catch (Throwable) {
        $_SESSION["msg"] = "Não foi possível restaurar este arquivo.";
    }
    back();
}
if ($module === "reports" && isset($_GET["export"])) {
    require_perm("reports.export");
    require_perm("reports.export");
    require_perm("reports.export");
    $from = preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET["from"] ?? "")
        ? $_GET["from"]
        : date("Y-m-01");
    $to = preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET["to"] ?? "")
        ? $_GET["to"]
        : date("Y-m-d");
    $s = db()->prepare(
        "SELECT date,type,description,amount,status FROM finance WHERE date BETWEEN ? AND ? ORDER BY date",
    );
    $s->execute([$from, $to]);
    header("Content-Type:text/csv; charset=UTF-8");
    header(
        "Content-Disposition:attachment; filename=relatorio-financeiro-" .
            $from .
            "-" .
            $to .
            ".csv",
    );
    echo "\xEF\xBB\xBFData;Tipo;Descrição;Valor;Status\n";
    foreach ($s as $r) {
        echo implode(";", [
            $r["date"],
            $r["type"],
            str_replace(";", ",", $r["description"]),
            number_format($r["amount"], 2, ",", ""),
            $r["status"],
        ]) . "\n";
    }
    audit("Relatório exportado", $from . " a " . $to);
    exit();
}
if (isset($_GET["delete"]) && isset($tables[$module])) {
    verify_csrf($_GET["csrf"] ?? "");
    require_perm($module . ".manage");
    require_perm($module . ".manage");
    require_perm($module . ".manage");
    try {
        if (in_array($module, ["users", "roles"], true)) {
            db()
                ->prepare(
                    "UPDATE " . $tables[$module] . " SET active=0 WHERE id=?",
                )
                ->execute([(int) $_GET["delete"]]);
        } else {
            db()
                ->prepare("DELETE FROM " . $tables[$module] . " WHERE id=?")
                ->execute([(int) $_GET["delete"]]);
        }
        $_SESSION["msg"] = "Registro excluído.";
    } catch (Throwable) {
        $_SESSION["msg"] = "Este registro está em uso e não pode ser excluído.";
    }
    back();
}
$edit = [];
if (isset($_GET["edit"]) && isset($tables[$module])) {
    $s = db()->prepare("SELECT * FROM " . $tables[$module] . " WHERE id=?");
    $s->execute([(int) $_GET["edit"]]);
    $edit = $s->fetch() ?: [];
}
if ($_POST && isset($tables[$module])) {
    require_perm($module . ".manage");
    try {
        $id = (int) ($_POST["id"] ?? 0);
        if ($module === "clients") {
            $d = [
                trim($_POST["name"]),
                trim($_POST["phone"]),
                trim($_POST["notes"]),
            ];
            $q = $id
                ? "UPDATE clients SET name=?,phone=?,notes=? WHERE id=?"
                : "INSERT INTO clients(name,phone,notes) VALUES(?,?,?)";
        } elseif ($module === "services") {
            $d = [
                trim($_POST["name"]),
                $_POST["price"],
                $_POST["duration"],
                isset($_POST["active"]) ? 1 : 0,
            ];
            $q = $id
                ? "UPDATE services SET name=?,price=?,duration=?,active=? WHERE id=?"
                : "INSERT INTO services(name,price,duration,active) VALUES(?,?,?,?)";
        } elseif ($module === "barbers") {
            $d = [
                trim($_POST["name"]),
                trim($_POST["phone"]),
                max(0, min(100, (float) ($_POST["commission_pct"] ?? 0))),
                isset($_POST["active"]) ? 1 : 0,
            ];
            $q = $id
                ? "UPDATE barbers SET name=?,phone=?,commission_pct=?,active=? WHERE id=?"
                : "INSERT INTO barbers(name,phone,commission_pct,active) VALUES(?,?,?,?)";
        } elseif ($module === "inventory") {
            $d = [
                trim($_POST["name"]),
                max(0, (float) $_POST["stock"]),
                max(0, (float) $_POST["min_stock"]),
                isset($_POST["active"]) ? 1 : 0,
            ];
            $q = $id
                ? "UPDATE inventory SET name=?,stock=?,min_stock=?,active=? WHERE id=?"
                : "INSERT INTO inventory(name,stock,min_stock,active) VALUES(?,?,?,?)";
        } elseif ($module === "appointments") {
            $start = $_POST["date"] . " " . $_POST["time"] . ":00";
            $weekday = (int) date("N", strtotime($start));
            $workDays = explode(",", setting("work_days", "1,2,3,4,5,6"));
            $time = $_POST["time"];
            $duration = (int) db()
                ->query(
                    "SELECT duration FROM services WHERE id=" .
                        (int) $_POST["service_id"],
                )
                ->fetchColumn();
            $end = date(
                "Y-m-d H:i:s",
                strtotime($start . " +" . $duration . " minutes"),
            );
            if (
                !in_array((string) $weekday, $workDays, true) ||
                $time < setting("open_time", "08:00") ||
                date("H:i", strtotime($end)) > setting("close_time", "19:00") ||
                ($time < setting("lunch_end", "13:00") &&
                    date("H:i", strtotime($end)) >
                        setting("lunch_start", "12:00"))
            ) {
                throw new Exception("Horário fora do expediente configurado.");
            }
            $conf = db()->prepare(
                "SELECT COUNT(*) FROM appointments a JOIN services s ON s.id=a.service_id WHERE a.id<>? AND a.barber_id=? AND a.status<>'Cancelado' AND a.start_at < ? AND DATE_ADD(a.start_at,INTERVAL s.duration MINUTE) > ?",
            );
            $conf->execute([$id, $_POST["barber_id"], $end, $start]);
            if ($conf->fetchColumn()) {
                throw new Exception(
                    "O horário se sobrepõe a outro atendimento deste barbeiro.",
                );
            }
            $block = db()->prepare(
                "SELECT COUNT(*) FROM barber_blocks WHERE barber_id=? AND start_at<? AND end_at>?",
            );
            $block->execute([$_POST["barber_id"], $end, $start]);
            if ($block->fetchColumn()) {
                throw new Exception(
                    "Este profissional está de folga ou com o horário bloqueado.",
                );
            }
            $d = [
                $_POST["client_id"],
                $_POST["service_id"],
                $_POST["barber_id"],
                $start,
                $_POST["status"],
                trim($_POST["notes"]),
            ];
            $q = $id
                ? "UPDATE appointments SET client_id=?,service_id=?,barber_id=?,start_at=?,status=?,notes=? WHERE id=?"
                : "INSERT INTO appointments(client_id,service_id,barber_id,start_at,status,notes) VALUES(?,?,?,?,?,?)";
        } elseif ($module === "finance") {
            $d = [
                $_POST["type"],
                trim($_POST["description"]),
                $_POST["amount"],
                $_POST["date"],
                $_POST["status"],
                $_POST["payment_method"] ?? "Dinheiro",
            ];
            $q = $id
                ? "UPDATE finance SET type=?,description=?,amount=?,date=?,status=?,payment_method=? WHERE id=?"
                : "INSERT INTO finance(type,description,amount,date,status,payment_method) VALUES(?,?,?,?,?,?)";
        } elseif ($module === "users") {
            if ($id && empty($_POST["password"])) {
                $d = [
                    trim($_POST["name"]),
                    trim($_POST["login"]),
                    $_POST["role_id"],
                    isset($_POST["active"]) ? 1 : 0,
                ];
                $q =
                    "UPDATE users SET name=?,email=?,role_id=?,active=? WHERE id=?";
            } else {
                $d = [
                    trim($_POST["name"]),
                    trim($_POST["login"]),
                    password_hash($_POST["password"], PASSWORD_DEFAULT),
                    $_POST["role_id"],
                    isset($_POST["active"]) ? 1 : 0,
                ];
                $q = $id
                    ? "UPDATE users SET name=?,email=?,password=?,role_id=?,active=? WHERE id=?"
                    : "INSERT INTO users(name,email,password,role_id,active) VALUES(?,?,?,?,?)";
            }
        } else {
            $rolePermissions =
                $id === 1 ? "all" : implode(",", $_POST["permissions"] ?? []);
            $roleActive = $id === 1 ? 1 : (isset($_POST["active"]) ? 1 : 0);
            $d = [trim($_POST["name"]), $rolePermissions, $roleActive];
            $q = $id
                ? "UPDATE roles SET name=?,permissions=?,active=? WHERE id=?"
                : "INSERT INTO roles(name,permissions,active) VALUES(?,?,?)";
        }
        if ($id) {
            $d[] = $id;
        }
        db()->prepare($q)->execute($d);
        $savedId = $id ?: db()->lastInsertId();
        if (
            $module === "users" &&
            trim($_POST["professional_name"] ?? "") !== ""
        ) {
            $professionalName = trim($_POST["professional_name"]);
            $s = db()->prepare("SELECT id FROM barbers WHERE user_id=?");
            $s->execute([$savedId]);
            $barberId = (int) $s->fetchColumn();
            if ($barberId) {
                db()
                    ->prepare("UPDATE barbers SET name=?,active=? WHERE id=?")
                    ->execute([
                        $professionalName,
                        isset($_POST["active"]) ? 1 : 0,
                        $barberId,
                    ]);
            } else {
                db()
                    ->prepare(
                        "INSERT INTO barbers(name,active,user_id) VALUES(?,?,?)",
                    )
                    ->execute([
                        $professionalName,
                        isset($_POST["active"]) ? 1 : 0,
                        $savedId,
                    ]);
            }
        }
        if ($module === "appointments" && $_POST["status"] === "Concluído") {
            db()->beginTransaction();
            try {
                $s = db()->prepare(
                    "SELECT a.id,a.start_at,s.name,s.price FROM appointments a JOIN services s ON s.id=a.service_id WHERE a.id=? FOR UPDATE",
                );
                $s->execute([$savedId]);
                $ap = $s->fetch();
                $f = db()->prepare(
                    "INSERT IGNORE INTO finance(type,description,amount,date,status,appointment_id) VALUES('Receita',?,?,?,'Pago',?)",
                );
                $f->execute([
                    "Atendimento: " . $ap["name"],
                    $ap["price"],
                    date("Y-m-d", strtotime($ap["start_at"])),
                    $ap["id"],
                ]);
                db()
                    ->prepare(
                        "UPDATE appointments SET finance_created=1 WHERE id=?",
                    )
                    ->execute([$savedId]);
                db()->commit();
            } catch (Throwable $x) {
                db()->rollBack();
                throw $x;
            }
        }
        $historyAction = $id ? "Agendamento editado" : "Agendamento criado";
        if ($module === "appointments") {
            db()
                ->prepare(
                    "INSERT INTO appointment_history(appointment_id,user_id,action,details) VALUES(?,?,?,?)",
                )
                ->execute([
                    $savedId,
                    $_SESSION["user"]["id"],
                    $historyAction,
                    "Status: " . $_POST["status"],
                ]);
        }
        audit($id ? "Registro editado" : "Registro criado", $module);
        $_SESSION["msg"] = "Salvo com sucesso.";
    } catch (Throwable $ex) {
        $_SESSION["msg"] =
            $ex->getMessage() === "Já existe um horário agendado neste momento."
                ? $ex->getMessage()
                : "Não foi possível salvar. Confira os dados.";
    }
    back();
}
$title = $titles[$module];
$business = setting("business_name", "BarberPro");
?><!doctype html><html lang="pt-BR"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width"><link rel="stylesheet" href="style.css"><link rel="stylesheet" href="professional.css"><title><?= e(
    $title,
) ?> | BarberPro</title></head><body><aside><div class="logo"><span class="logo-mark">✂</span><span>BARBER<b>PRO</b></span></div><nav><?php foreach (
     $titles
     as $key => $label
 ):
     $menuPermission = in_array($key, ["weekly", "blocks", "waitlist"], true)
         ? "appointments"
         : $key;
     $showMenu =
         in_array($key, ["dashboard", "security", "profile"], true) ||
         has_perm($menuPermission . ".view");
     if (
         $key === "users" &&
         ($_SESSION["user"]["role"] ?? "") !== "Administrador"
     ) {
         $showMenu = false;
     }
     if ($showMenu): ?><a class="<?= $module === $key
    ? "on"
    : "" ?>" href="<?= $files[$key] ?>"><?= e($label) ?></a><?php endif;
 endforeach; ?></nav></aside><main><header><div><h1><?= e(
    $title,
) ?></h1><p>Gestão inteligente da sua barbearia</p></div><div class="header-actions"><div class="notification-wrap"><button class="notification-bell" id="notificationBell" type="button" onclick="toggleNotifications(event)">🔔<span id="notificationCount"></span></button><div class="notification-panel" id="notificationPanel"><div class="notification-head"><b>Novos agendamentos</b><small>Solicitações feitas no site</small></div><div id="notificationList"><p class="notification-empty">Nenhum agendamento novo.</p></div><a class="notification-all" href="agenda.php">Abrir agenda completa</a></div></div><div class="top-user-wrap"><button class="top-user" type="button" onclick="toggleUserMenu(event)"><div class="top-avatar"><?= e(
    mb_strtoupper(mb_substr($_SESSION["user"]["name"], 0, 1)),
) ?></div><div><b><?= e($_SESSION["user"]["name"]) ?></b><small><?= e(
    $_SESSION["user"]["role"],
) ?> · <?= date(
     "d/m/Y",
 ) ?></small></div><span class="user-caret">⌄</span></button><div class="user-dropdown" id="userDropdown"><div class="dropdown-head"><b><?= e(
    $_SESSION["user"]["name"],
) ?></b><small><?= e(
    $_SESSION["user"]["email"],
) ?></small></div><a href="perfil.php">Meu perfil</a><a href="seguranca.php">Alterar senha</a><div class="dropdown-line"></div><a class="logout-link" href="?logout=1">Sair do sistema</a></div></div></div></header><section><div class="booking-toast" id="bookingToast"><span>🔔</span><div><b>Novo agendamento recebido!</b><small id="bookingToastText"></small></div><button type="button" onclick="toggleNotifications(event)">Ver</button></div><?php if (
    $msg = $_SESSION["msg"] ?? ""
):
    unset($_SESSION["msg"]); ?><div class="success"><?= e($msg) ?></div><?php
endif; ?>
<?php if ($module === "dashboard"):

    $clients = db()->query("SELECT COUNT(*) FROM clients")->fetchColumn();
    $today = db()
        ->query(
            "SELECT COUNT(*) FROM appointments WHERE DATE(start_at)=CURDATE() AND status<>'Cancelado'",
        )
        ->fetchColumn();
    $pending = db()
        ->query(
            "SELECT COUNT(*) FROM appointments WHERE status='Pendente' AND start_at>=NOW()",
        )
        ->fetchColumn();
    $doneToday = db()
        ->query(
            "SELECT COUNT(*) FROM appointments WHERE DATE(start_at)=CURDATE() AND status='Concluído'",
        )
        ->fetchColumn();
    $canceledMonth = db()
        ->query(
            "SELECT COUNT(*) FROM appointments WHERE MONTH(start_at)=MONTH(CURDATE()) AND YEAR(start_at)=YEAR(CURDATE()) AND status='Cancelado'",
        )
        ->fetchColumn();
    $doneMonth = db()
        ->query(
            "SELECT COUNT(*) FROM appointments WHERE MONTH(start_at)=MONTH(CURDATE()) AND YEAR(start_at)=YEAR(CURDATE()) AND status='Concluído'",
        )
        ->fetchColumn();
    $month = db()
        ->query(
            "SELECT COALESCE(SUM(IF(type='Receita',amount,-amount)),0) FROM finance WHERE status='Pago' AND date>=DATE_FORMAT(CURDATE(),'%Y-%m-01') AND date<DATE_ADD(LAST_DAY(CURDATE()),INTERVAL 1 DAY)",
        )
        ->fetchColumn();
    $income = db()
        ->query(
            "SELECT COALESCE(SUM(amount),0) FROM finance WHERE type='Receita' AND status='Pago' AND date>=DATE_FORMAT(CURDATE(),'%Y-%m-01')",
        )
        ->fetchColumn();
    $next = db()
        ->query(
            "SELECT a.*,c.name client,s.name service FROM appointments a JOIN clients c ON c.id=a.client_id JOIN services s ON s.id=a.service_id WHERE a.start_at>=NOW() AND a.status<>'Cancelado' ORDER BY a.start_at LIMIT 6",
        )
        ->fetchAll();
    ?><div class="welcome"><div><small>RESUMO DO MÊS</small><h2>Olá, <?= e(
    explode(" ", $_SESSION["user"]["name"])[0],
) ?>!</h2></div><div class="welcome-icon">✂</div></div><div class="stats three"><article><small>Clientes cadastrados</small><strong><?= $clients ?></strong><em>Base total</em></article><article><small>Horários hoje</small><strong><?= $today ?></strong><em>Atendimentos ativos</em></article><?php if (
    in_array($_SESSION["user"]["role"], ["Administrador", "Gerente"], true)
): ?><article><small>Receitas do mês</small><strong><?= money(
    $income,
) ?></strong><em>Atendimentos concluídos</em></article><?php endif; ?><article><small>Concluídos hoje</small><strong><?= $doneToday ?></strong><em>Atendimentos finalizados</em></article></div><div class="dashboard-grid"><div class="card"><div class="card-title"><h2>Próximos horários</h2><a href="agenda.php">Ver agenda</a></div><div class="table"><table><thead><tr><th>Data</th><th>Cliente</th><th>Serviço</th><th>Status</th></tr></thead><tbody><?php foreach (
    $next
    as $r
): ?><tr><td><?= date("d/m H:i", strtotime($r["start_at"])) ?></td><td><?= e(
    $r["client"],
) ?></td><td><?= e($r["service"]) ?></td><td><span class="badge"><?= e(
    $r["status"],
) ?></span></td></tr><?php endforeach; ?></tbody></table><?php if (
    !$next
): ?><p class="empty">Nenhum horário futuro.</p><?php endif; ?></div></div><div class="card quick"><h2>Ações rápidas</h2><a class="btn" href="agenda.php">+ Agendar horário</a><a class="btn gray" href="clientes.php">+ Novo cliente</a><div class="pending"><strong><?= $pending ?></strong><span>agendamento(s) aguardando confirmação</span></div></div></div><div class="insight-grid <?= in_array(
    $_SESSION["user"]["role"],
    ["Administrador", "Gerente"],
    true,
)
    ? ""
    : "no-finance" ?>"><div class="insight"><span class="insight-dot red"></span><div><small>Pendentes futuros</small><b><?= $pending ?></b></div></div><div class="insight"><span class="insight-dot green"></span><div><small>Concluídos no mês</small><b><?= $doneMonth ?></b></div></div><div class="insight"><span class="insight-dot yellow"></span><div><small>Cancelados no mês</small><b><?= $canceledMonth ?></b></div></div><?php if (
    in_array($_SESSION["user"]["role"], ["Administrador", "Gerente"], true)
): ?><div class="insight"><span class="insight-dot blue"></span><div><small>Ticket médio</small><b><?= money(
    $doneMonth ? $income / $doneMonth : 0,
) ?></b></div></div><?php endif; ?></div>
<?php
elseif ($module === "profile"): ?>
<div class="profile-hero"><div class="profile-avatar"><?= e(
    mb_strtoupper(mb_substr($_SESSION["user"]["name"], 0, 1)),
) ?></div><div><small>MINHA CONTA</small><h2><?= e(
    $_SESSION["user"]["name"],
) ?></h2><p><?= e(
    $_SESSION["user"]["role"],
) ?></p></div><a class="btn" href="seguranca.php">Alterar minha senha</a></div><div class="dashboard-grid"><div class="card profile-details"><h2>Dados de acesso</h2><div class="detail-row"><span>Nome</span><b><?= e(
    $_SESSION["user"]["name"],
) ?></b></div><div class="detail-row"><span>Login</span><b><?= e(
    $_SESSION["user"]["email"],
) ?></b></div><div class="detail-row"><span>Cargo</span><b><?= e(
    $_SESSION["user"]["role"],
) ?></b></div><div class="detail-row"><span>Situação</span><b class="status-ok">Acesso ativo</b></div></div><div class="card"><h2>Meus acessos</h2><p class="muted-text">Estas permissões são definidas pelo administrador através do seu cargo.</p><div class="permission-chips profile-permissions"><?= permission_chips(
    $_SESSION["user"]["permissions"],
) ?></div></div></div>
<?php elseif ($module === "reports"):

    $from = preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET["from"] ?? "")
        ? $_GET["from"]
        : date("Y-m-01");
    $to = preg_match('/^\d{4}-\d{2}-\d{2}$/', $_GET["to"] ?? "")
        ? $_GET["to"]
        : date("Y-m-d");
    $s = db()->prepare(
        "SELECT COALESCE(SUM(IF(type='Receita' AND status='Pago',amount,0)),0) income,COALESCE(SUM(IF(type='Despesa' AND status='Pago',amount,0)),0) expense FROM finance WHERE date BETWEEN ? AND ?",
    );
    $s->execute([$from, $to]);
    $tot = $s->fetch();
    $s = db()->prepare(
        "SELECT s.name,COUNT(*) qty,COALESCE(SUM(s.price),0) total FROM appointments a JOIN services s ON s.id=a.service_id WHERE DATE(a.start_at) BETWEEN ? AND ? AND a.status='Concluído' GROUP BY s.id ORDER BY qty DESC LIMIT 10",
    );
    $s->execute([$from, $to]);
    $topServices = $s->fetchAll();
    $s = db()->prepare(
        "SELECT b.name,b.commission_pct,COUNT(*) qty,COALESCE(SUM(s.price),0) total,COALESCE(SUM(s.price)*b.commission_pct/100,0) commission FROM appointments a JOIN barbers b ON b.id=a.barber_id JOIN services s ON s.id=a.service_id WHERE DATE(a.start_at) BETWEEN ? AND ? AND a.status='Concluído' GROUP BY b.id ORDER BY total DESC",
    );
    $s->execute([$from, $to]);
    $barberResults = $s->fetchAll();
    $s = db()->prepare(
        "SELECT COUNT(*) total,SUM(status='Concluído') done,SUM(status='Cancelado') canceled FROM appointments WHERE DATE(start_at) BETWEEN ? AND ?",
    );
    $s->execute([$from, $to]);
    $appointmentsResult = $s->fetch();
    ?>
<div class="card"><form method="get" class="filter-row"><div><?= field(
    "from",
    "Data inicial",
    "date",
    $from,
) ?></div><div><?= field(
    "to",
    "Data final",
    "date",
    $to,
) ?></div><button>Atualizar relatório</button><a class="btn gray" href="relatorios.php?export=1&from=<?= e(
    $from,
) ?>&to=<?= e(
    $to,
) ?>">Exportar CSV</a></form></div><div class="stats four"><article><small>Receitas</small><strong><?= money(
    $tot["income"],
) ?></strong><em>No período</em></article><article><small>Despesas</small><strong><?= money(
    $tot["expense"],
) ?></strong><em>No período</em></article><article><small>Resultado</small><strong><?= money(
    $tot["income"] - $tot["expense"],
) ?></strong><em>Saldo líquido</em></article><article><small>Atendimentos</small><strong><?= intval(
    $appointmentsResult["done"],
) ?></strong><em><?= intval(
    $appointmentsResult["canceled"],
) ?> cancelado(s)</em></article></div><div class="dashboard-grid"><div class="card table"><h2>Serviços mais realizados</h2><table><thead><tr><th>Serviço</th><th>Quantidade</th><th>Total</th></tr></thead><tbody><?php foreach (
     $topServices
     as $r
 ): ?><tr><td><?= e($r["name"]) ?></td><td><?= $r["qty"] ?></td><td><?= money(
    $r["total"],
) ?></td></tr><?php endforeach; ?></tbody></table></div><div class="card table"><h2>Resultado por barbeiro</h2><table><thead><tr><th>Barbeiro</th><th>Atendimentos</th><th>Total</th><th>Comissão</th><th>Comissão</th></tr></thead><tbody><?php foreach (
    $barberResults
    as $r
): ?><tr><td><?= e($r["name"]) ?></td><td><?= $r["qty"] ?></td><td><?= money(
    $r["total"],
) ?></td><td><?= money(
    $r["commission"],
) ?></td></tr><?php endforeach; ?></tbody></table></div></div>
<?php
elseif ($module === "settings"):
    $days = explode(",", setting("work_days", "1,2,3,4,5,6")); ?>
<div class="card"><h2>Dados e funcionamento</h2><form method="post" class="settings-form"><?=
field(
    "business_name",
    "Nome da barbearia",
    "text",
    setting("business_name", "BarberPro"),
)
. field("phone", "Telefone", "text", setting("phone"), false)
. field("address", "Endereço", "text", setting("address"), false)
?><div class="form-row"><?=
field("open_time", "Abertura", "time", setting("open_time", "08:00"))
. field("close_time", "Fechamento", "time", setting("close_time", "19:00"))
. field(
    "lunch_start",
    "Início do intervalo",
    "time",
    setting("lunch_start", "12:00"),
)
. field("lunch_end", "Fim do intervalo", "time", setting("lunch_end", "13:00"))
?></div><label>Dias de funcionamento</label><div class="checks"><?php foreach (
    [
        1 => "Segunda",
        2 => "Terça",
        3 => "Quarta",
        4 => "Quinta",
        5 => "Sexta",
        6 => "Sábado",
        7 => "Domingo",
    ]
    as $n => $day
): ?><label><input class="auto" type="checkbox" name="work_days[]" value="<?= $n ?>" <?= in_array(
    (string) $n,
    $days,
)
    ? "checked"
    : "" ?>> <?= $day ?></label><?php endforeach; ?></div><div class="public-booking-settings"><div><h3>Agendamento online</h3><p>Permita que clientes escolham horários disponíveis diretamente pelo site.</p><a class="btn gray" target="_blank" href="agendar.php">Abrir página do cliente ↗</a></div><div><label><input class="auto" type="checkbox" name="public_booking_enabled" <?= setting(
    "public_booking_enabled",
    "1",
) === "1"
    ? "checked"
    : "" ?>> Agendamento público ativo</label><?=
field(
    "booking_interval",
    "Intervalo entre opções (minutos)",
    "number",
    setting("booking_interval", "30"),
)
. field(
    "booking_notice",
    "Mensagem após agendar",
    "text",
    setting("booking_notice", "Seu horário será confirmado pela barbearia."),
)
?></div></div><button>Salvar configurações</button></form></div>
<?php
elseif ($module === "security"):
    $logs =
        ($_SESSION["user"]["role"] ?? "") === "Administrador"
            ? db()
                ->query(
                    "SELECT a.*,u.name user_name FROM audit_logs a LEFT JOIN users u ON u.id=a.user_id ORDER BY a.id DESC LIMIT 30",
                )
                ->fetchAll()
            : []; ?>
<div class="dashboard-grid"><div class="card"><h2>Alterar minha senha</h2><form method="post"><input type="hidden" name="action" value="password"><?=
field("current_password", "Senha atual", "password", "")
. field("new_password", "Nova senha (mínimo 8 caracteres)", "password", "")
. field("confirm_password", "Confirmar nova senha", "password", "")
?><button>Alterar senha</button></form></div><div class="card"><h2>Cuidados de segurança</h2><p>Use uma senha exclusiva com pelo menos 8 caracteres.</p><p>Desative logins que não são mais utilizados.</p><p>Faça backups regularmente.</p></div></div><?php if (
    ($_SESSION["user"]["role"] ?? "") ===
    "Administrador"
): ?><div class="card recovery-card"><div><h2>Recuperação administrativa</h2><p>Defina um código secreto para recuperar sua senha caso perca o acesso. Use pelo menos 10 caracteres e guarde fora do computador.</p><a href="recuperar.php">Abrir página de recuperação</a></div><form method="post"><input type="hidden" name="action" value="recovery"><?=
field("current_password", "Senha atual", "password", "")
. field("recovery_code", "Novo código de recuperação", "password", "")
?><button>Salvar código seguro</button></form></div><?php endif; ?><div class="card table"><h2>Atividades recentes</h2><table><thead><tr><th>Data</th><th>Usuário</th><th>Ação</th><th>Detalhes</th></tr></thead><tbody><?php foreach (
    $logs
    as $r
): ?><tr><td><?= date(
    "d/m/Y H:i",
    strtotime($r["created_at"]),
) ?></td><td><?= e($r["user_name"]) ?></td><td><?= e(
    $r["action"],
) ?></td><td><?= e(
    $r["details"],
) ?></td></tr><?php endforeach; ?></tbody></table></div>
<?php
elseif ($module === "backups"): ?>
<div class="dashboard-grid"><div class="card"><h2>Baixar cópia de segurança</h2><p>Salva clientes, agenda, financeiro, serviços, profissionais, usuários e configurações.</p><a class="btn" href="backup.php?download=1">Baixar backup agora</a></div><div class="card"><h2>Restaurar backup</h2><p>A restauração substitui os dados atuais pelos dados do arquivo.</p><form method="post" enctype="multipart/form-data" onsubmit="return confirm('Restaurar este backup?')"><input type="file" name="backup" accept=".sql" required><label>Confirme sua senha administrativa</label><input type="password" name="confirm_password" required><button>Restaurar arquivo</button></form></div></div>
<?php elseif ($module === "blocks"):

    $barberList = db()
        ->query("SELECT id,name FROM barbers WHERE active=1 ORDER BY name")
        ->fetchAll();
    $rows = db()
        ->query(
            "SELECT bb.*,b.name barber,u.name creator FROM barber_blocks bb JOIN barbers b ON b.id=bb.barber_id LEFT JOIN users u ON u.id=bb.created_by WHERE bb.end_at>=NOW() ORDER BY bb.start_at",
        )
        ->fetchAll();
    ?>
<div class="actions"><span><?= count(
    $rows,
) ?> bloqueio(s) futuro(s)</span><button onclick="openForm()">+ Bloquear horário ou folga</button></div><div class="card table"><table><thead><tr><th>Profissional</th><th>Início</th><th>Fim</th><th>Motivo</th><th>Ação</th></tr></thead><tbody><?php foreach (
     $rows
     as $r
 ): ?><tr><td><b><?= e($r["barber"]) ?></b></td><td><?= date(
    "d/m/Y H:i",
    strtotime($r["start_at"]),
) ?></td><td><?= date("d/m/Y H:i", strtotime($r["end_at"])) ?></td><td><?= e(
    $r["reason"],
) ?></td><td><a class="del" href="bloqueios.php?remove_block=<?= $r[
    "id"
] ?>&csrf=<?= csrf_token() ?>" onclick="return confirm('Liberar este horário?')">Liberar</a></td></tr><?php endforeach; ?></tbody></table></div><div class="modal" id="modal"><form method="post" class="form"><a class="x" href="bloqueios.php">×</a><h2>Bloquear horário</h2><label>Profissional</label><select name="barber_id"><?php foreach (
    $barberList
    as $b
): ?><option value="<?= $b["id"] ?>"><?= e(
    $b["name"],
) ?></option><?php endforeach; ?></select><div class="form-row"><?=
field("start_date", "Data inicial", "date", date("Y-m-d"))
. field("start_time", "Hora inicial", "time", "08:00")
. field("end_date", "Data final", "date", date("Y-m-d"))
. field("end_time", "Hora final", "time", "19:00")
?></div><?= field(
    "reason",
    "Motivo (folga, almoço, férias...)",
    "text",
    "",
) ?><button>Salvar bloqueio</button></form></div>
<?php
elseif ($module === "waitlist"):
    $rows = db()
        ->query(
            "SELECT w.*,s.name service,b.name barber FROM waitlist w LEFT JOIN services s ON s.id=w.service_id LEFT JOIN barbers b ON b.id=w.barber_id ORDER BY w.status='Aguardando' DESC,w.created_at",
        )
        ->fetchAll(); ?>
<div class="actions"><span><?= count(
    $rows,
) ?> pessoa(s) na lista</span></div><div class="card table"><table><thead><tr><th>Cliente</th><th>Telefone</th><th>Preferência</th><th>Status</th><th>Ações</th></tr></thead><tbody><?php foreach (
     $rows
     as $r
 ):
     $text =
         "Olá " .
         $r["name"] .
         "! Surgiu um horário disponível na barbearia. Gostaria de agendar?"; ?><tr><td><b><?= e(
    $r["name"],
) ?></b><small><?= date(
    "d/m/Y H:i",
    strtotime($r["created_at"]),
) ?></small></td><td><?= e($r["phone"]) ?></td><td><?= e(
    ($r["service"] ?: "Qualquer serviço") .
        " · " .
        ($r["barber"] ?: "Qualquer profissional") .
        ($r["preferred_date"]
            ? " · " . date("d/m/Y", strtotime($r["preferred_date"]))
            : ""),
) ?></td><td><span class="badge"><?= e(
    $r["status"],
) ?></span></td><td><a class="whatsapp" target="_blank" href="https://wa.me/55<?= preg_replace(
    "/\D/",
    "",
    $r["phone"],
) ?>?text=<?= urlencode(
    $text,
) ?>">Avisar no WhatsApp</a> <a class="edit" href="lista_espera.php?served=<?= $r[
    "id"
] ?>&csrf=<?= csrf_token() ?>">Marcar avisado</a> <a class="del" href="lista_espera.php?remove_wait=<?= $r[
    "id"
] ?>&csrf=<?= csrf_token() ?>">Remover</a></td></tr><?php
 endforeach; ?></tbody></table></div>
<?php
elseif ($module === "weekly"):

    $weekInput = $_GET["week"] ?? date("Y-m-d");
    $base = strtotime($weekInput);
    $monday = date("Y-m-d", strtotime("monday this week", $base));
    $sunday = date("Y-m-d", strtotime($monday . " +6 days"));
    $s = db()->prepare(
        "SELECT a.*,c.name client,c.phone,s.name service,b.name barber FROM appointments a JOIN clients c ON c.id=a.client_id JOIN services s ON s.id=a.service_id LEFT JOIN barbers b ON b.id=a.barber_id WHERE DATE(a.start_at) BETWEEN ? AND ? AND a.status<>'Cancelado' ORDER BY a.start_at",
    );
    $s->execute([$monday, $sunday]);
    $weekRows = $s->fetchAll();
    $byDay = [];
    foreach ($weekRows as $r) {
        $byDay[date("Y-m-d", strtotime($r["start_at"]))][] = $r;
    }
    ?>
<div class="week-toolbar"><a class="btn gray" href="agenda_semanal.php?week=<?= date(
    "Y-m-d",
    strtotime($monday . " -7 days"),
) ?>">← Semana anterior</a><div><small>SEMANA</small><h2><?= date(
    "d/m",
    strtotime($monday),
) ?> a <?= date(
     "d/m/Y",
     strtotime($sunday),
 ) ?></h2></div><a class="btn gray" href="agenda_semanal.php?week=<?= date(
    "Y-m-d",
    strtotime($monday . " +7 days"),
) ?>">Próxima semana →</a></div><div class="weekly-calendar"><?php
$dayNames = [
    "Segunda",
    "Terça",
    "Quarta",
    "Quinta",
    "Sexta",
    "Sábado",
    "Domingo",
];
for ($i = 0; $i < 7; $i++):
    $day = date(
        "Y-m-d",
        strtotime($monday . " +$i days"),
    ); ?><div class="week-day <?= $day === date("Y-m-d")
    ? "today"
    : "" ?>"><div class="week-day-head"><b><?= $dayNames[
    $i
] ?></b><span><?= date(
    "d/m",
    strtotime($day),
) ?></span></div><div class="week-events"><?php
foreach (
    $byDay[$day] ?? []
    as $r
): ?><a class="week-event status-<?= strtolower(
    e($r["status"]),
) ?>" href="agenda.php?edit=<?= $r["id"] ?>"><time><?= date(
    "H:i",
    strtotime($r["start_at"]),
) ?></time><b><?= e($r["client"]) ?></b><small><?= e(
    $r["service"],
) ?></small><em><?= e(
    $r["barber"] ?: "Sem barbeiro",
) ?></em></a><?php endforeach;
if (
    empty($byDay[$day])
): ?><div class="week-empty">Sem horários</div><?php endif;
?></div></div><?php
endfor;
?></div>
<?php
elseif ($module === "inventory"):

    $search = trim($_GET["search"] ?? "");
    $rows = db()
        ->query("SELECT * FROM inventory ORDER BY active DESC,name")
        ->fetchAll();
    if ($search) {
        $rows = array_values(
            array_filter(
                $rows,
                fn($r) => stripos($r["name"], $search) !== false,
            ),
        );
    }
    $low = array_filter(
        $rows,
        fn($r) => (float) $r["stock"] < (float) $r["min_stock"],
    );
    ?>
<div class="stats two"><article><small>Produtos cadastrados</small><strong><?= count(
    $rows,
) ?></strong><em>Itens controlados</em></article><article class="<?= count($low)
    ? "stat-warning"
    : "" ?>"><small>Precisam de reposição</small><strong><?= count(
    $low,
) ?></strong><em>Abaixo da quantidade necessária</em></article></div><div class="actions"><span><?= count(
    $rows,
) ?> produto(s)</span><button onclick="openForm()">+ Novo produto</button></div><form class="search"><input name="search" value="<?= e(
     $search,
 ) ?>" placeholder="Pesquisar produto"><button>Pesquisar</button></form><div class="card table"><table><thead><tr><th>Produto</th><th>Quantidade atual</th><th>Quantidade necessária</th><th>Situação</th><th>Ações</th></tr></thead><tbody><?php foreach (
    $rows
    as $r
):
    $needs =
        (float) $r["stock"] < (float) $r["min_stock"]; ?><tr class="<?= $needs
    ? "low-stock"
    : "" ?>"><td><b><?= e($r["name"]) ?></b></td><td><strong><?= number_format(
    (float) $r["stock"],
    0,
    ",",
    ".",
) ?></strong></td><td><?= number_format(
    (float) $r["min_stock"],
    0,
    ",",
    ".",
) ?></td><td><span class="role-status <?= $needs
    ? "inactive"
    : "active" ?>"><?= $needs
    ? "Repor produto"
    : "Quantidade suficiente" ?></span></td><td><a class="edit" href="estoque.php?edit=<?= $r[
    "id"
] ?>">Editar</a> <a class="del" href="estoque.php?delete=<?= $r[
    "id"
] ?>" onclick="return confirm('Excluir produto?')">Excluir</a></td></tr><?php
endforeach; ?></tbody></table></div><div class="modal <?= !empty($edit)
    ? "show"
    : "" ?>" id="modal"><form method="post" class="form"><a class="x" href="estoque.php">×</a><h2><?= empty(
    $edit
)
    ? "Novo produto"
    : "Editar produto" ?></h2><input type="hidden" name="id" value="<?= e(
    $edit["id"] ?? 0,
) ?>"><?= field(
    "name",
    "Nome do produto",
    "text",
    $edit["name"] ?? "",
) ?><div class="form-row"><?=
field("stock", "Quantidade que tem", "number", $edit["stock"] ?? 0)
. field(
    "min_stock",
    "Quantidade que precisa ter",
    "number",
    $edit["min_stock"] ?? 0,
)
?></div><small class="field-help">O sistema avisará quando a quantidade atual ficar abaixo da necessária.</small><label><input class="auto" type="checkbox" name="active" <?= !isset(
    $edit["active"],
) || $edit["active"]
    ? "checked"
    : "" ?>> Produto ativo</label><button>Salvar produto</button></form></div><?php
elseif ($module === "barbers"):
    $rows = db()->query("SELECT * FROM barbers ORDER BY name")->fetchAll(); ?>
<div class="actions"><span><?= count(
    $rows,
) ?> profissional(is)</span><button onclick="openForm()">+ Novo barbeiro</button></div><div class="card table"><table><thead><tr><th>Profissional</th><th>Telefone</th><th>Comissão</th><th>Status</th><th>Ações</th></tr></thead><tbody><?php foreach (
     $rows
     as $r
 ): ?><tr><td><b><?= e($r["name"]) ?></b></td><td><?= e(
    $r["phone"],
) ?></td><td><?= number_format(
    (float) $r["commission_pct"],
    2,
    ",",
    ".",
) ?>%</td><td><?= $r["active"]
    ? "Ativo"
    : "Inativo" ?></td><td><a class="edit" href="barbeiros.php?edit=<?= $r[
    "id"
] ?>">Editar</a> <a class="del" href="barbeiros.php?delete=<?= $r[
    "id"
] ?>" onclick="return confirm('Excluir profissional?')">Excluir</a></td></tr><?php endforeach; ?></tbody></table></div><div class="modal <?= !empty(
    $edit
)
    ? "show"
    : "" ?>" id="modal"><form method="post" class="form"><a class="x" href="barbeiros.php">×</a><h2><?= empty(
    $edit
)
    ? "Novo barbeiro"
    : "Editar barbeiro" ?></h2><input type="hidden" name="id" value="<?= e(
    $edit["id"] ?? 0,
) ?>"><?=
field("name", "Nome do profissional", "text", $edit["name"] ?? "")
. field("phone", "Telefone", "text", $edit["phone"] ?? "", false)
. field("commission_pct", "Comissão (%)", "number", $edit["commission_pct"] ?? 0)
?><label><input class="auto" type="checkbox" name="active" <?= !isset(
    $edit["active"],
) || $edit["active"]
    ? "checked"
    : "" ?>> Profissional ativo</label><button>Salvar</button></form></div>
<?php
elseif ($module === "appointments"):

    $clientList = db()
        ->query("SELECT * FROM clients ORDER BY name")
        ->fetchAll();
    $serviceList = db()
        ->query("SELECT * FROM services WHERE active=1 ORDER BY name")
        ->fetchAll();
    $barberList = db()
        ->query("SELECT * FROM barbers WHERE active=1 ORDER BY name")
        ->fetchAll();
    $filter = trim($_GET["search"] ?? "");
    $sql =
        "SELECT a.*,c.name client,c.phone client_phone,s.name service,b.name barber FROM appointments a JOIN clients c ON c.id=a.client_id JOIN services s ON s.id=a.service_id LEFT JOIN barbers b ON b.id=a.barber_id";
    $rows = db()
        ->query($sql . " ORDER BY start_at DESC")
        ->fetchAll();
    if ($filter) {
        $rows = array_values(
            array_filter(
                $rows,
                fn($r) => stripos(
                    implode(" ", array_map("strval", $r)),
                    $filter,
                ) !== false,
            ),
        );
    }
    ?>
<?php if (isset($_GET["history"])):

    $hs = db()->prepare(
        "SELECT h.*,u.name user_name FROM appointment_history h LEFT JOIN users u ON u.id=h.user_id WHERE h.appointment_id=? ORDER BY h.created_at DESC",
    );
    $hs->execute([(int) $_GET["history"]]);
    ?><div class="card history-card"><div class="card-title"><h2>Histórico do agendamento</h2><a href="agenda.php">Fechar</a></div><?php foreach (
    $hs
    as $h
): ?><div class="history-event"><b><?= e($h["action"]) ?></b><span><?= e(
    $h["details"],
) ?></span><small><?= e($h["user_name"] ?: "Sistema/cliente") ?> · <?= date(
     "d/m/Y H:i",
     strtotime($h["created_at"]),
 ) ?></small></div><?php endforeach; ?></div><?php
endif; ?><div class="actions"><span><?= count(
    $rows,
) ?> horário(s)</span><button onclick="openForm()">+ Novo horário</button></div><form class="search"><input name="search" value="<?= e(
     $filter,
 ) ?>" placeholder="Pesquisar cliente, barbeiro ou status"><button>Pesquisar</button></form><div class="card table"><table><thead><tr><th>Data</th><th>Cliente</th><th>Serviço</th><th>Barbeiro</th><th>Status</th><th>Ações</th></tr></thead><tbody><?php foreach (
    $rows
    as $r
): ?><tr><td><?= date("d/m/Y H:i", strtotime($r["start_at"])) ?></td><td><?= e(
    $r["client"],
) ?></td><td><?= e($r["service"]) ?></td><td><?= e(
    $r["barber"] ?: "Não definido",
) ?></td><td><span class="badge"><?= e(
    $r["status"],
) ?></span></td><td><?php if (
    $r["status"] === "Pendente"
): ?><a class="confirm-booking" target="_blank" href="agenda.php?confirm=<?= $r[
    "id"
] ?>&csrf=<?= csrf_token() ?>" onclick="setTimeout(()=>location.reload(),1200)">✓ Aceitar e avisar</a><?php else: ?><a class="whatsapp" target="_blank" href="https://wa.me/55<?= preg_replace(
    "/\D/",
    "",
    $r["client_phone"],
) ?>?text=<?= urlencode(
    "Olá " .
        $r["client"] .
        "! Seu agendamento está confirmado para " .
        date("d/m/Y H:i", strtotime($r["start_at"])) .
        ".",
) ?>">WhatsApp</a><?php endif; ?> <a class="reminder" target="_blank" href="https://wa.me/55<?= preg_replace(
     "/\D/",
     "",
     $r["client_phone"],
 ) ?>?text=<?= urlencode(
    "Olá " .
        $r["client"] .
        "! Lembramos do seu horário: " .
        $r["service"] .
        " com " .
        ($r["barber"] ?: "nosso profissional") .
        " em " .
        date("d/m/Y", strtotime($r["start_at"])) .
        " às " .
        date("H:i", strtotime($r["start_at"])) .
        ". Esperamos você!",
) ?>">Lembrete</a> <a class="edit" href="agenda.php?history=<?= $r[
    "id"
] ?>">Histórico</a> <a class="edit" href="agenda.php?edit=<?= $r[
    "id"
] ?>">Editar</a> <a class="del" href="agenda.php?delete=<?= $r[
    "id"
] ?>" onclick="return confirm('Excluir horário?')">Excluir</a></td></tr><?php endforeach; ?></tbody></table></div><div class="modal <?= !empty(
    $edit
)
    ? "show"
    : "" ?>" id="modal"><form method="post" class="form"><a class="x" href="agenda.php">×</a><h2><?= empty(
    $edit
)
    ? "Novo horário"
    : "Editar horário" ?></h2><input type="hidden" name="id" value="<?= e(
    $edit["id"] ?? 0,
) ?>"><label>Cliente</label><select name="client_id" required><?php foreach (
    $clientList
    as $x
): ?><option value="<?= $x["id"] ?>" <?= ($edit["client_id"] ?? 0) == $x["id"]
    ? "selected"
    : "" ?>><?= e(
    $x["name"] . " - " . $x["phone"],
) ?></option><?php endforeach; ?></select><label>Serviço</label><select name="service_id" required><?php foreach (
    $serviceList
    as $x
): ?><option value="<?= $x["id"] ?>" <?= ($edit["service_id"] ?? 0) == $x["id"]
    ? "selected"
    : "" ?>><?= e(
    $x["name"],
) ?></option><?php endforeach; ?></select><label>Barbeiro</label><select name="barber_id" required><?php foreach (
    $barberList
    as $x
): ?><option value="<?= $x["id"] ?>" <?= ($edit["barber_id"] ?? 0) == $x["id"]
    ? "selected"
    : "" ?>><?= e($x["name"]) ?></option><?php endforeach; ?></select><?=
field(
    "date",
    "Data",
    "date",
    isset($edit["start_at"])
        ? date("Y-m-d", strtotime($edit["start_at"]))
        : date("Y-m-d"),
)
. field(
    "time",
    "Hora",
    "time",
    isset($edit["start_at"]) ? date("H:i", strtotime($edit["start_at"])) : "",
)
?> <label>Status</label><select name="status"><?php foreach (
     ["Pendente", "Confirmado", "Concluído", "Cancelado"]
     as $x
 ): ?><option <?= ($edit["status"] ?? "Pendente") === $x
    ? "selected"
    : "" ?>><?= $x ?></option><?php endforeach; ?></select><?= field(
    "notes",
    "Observação",
    "text",
    $edit["notes"] ?? "",
    false,
) ?><small>Horário: <?= e(setting("open_time", "08:00")) ?> às <?= e(
     setting("close_time", "19:00"),
 ) ?>. Intervalo: <?= e(setting("lunch_start", "12:00")) ?> às <?= e(
     setting("lunch_end", "13:00"),
 ) ?>.</small><button>Salvar horário</button></form></div>
<?php
elseif ($module === "history"):

    $cid = (int) ($_GET["client_id"] ?? 0);
    $client = null;
    $history = [];
    if ($cid) {
        $s = db()->prepare("SELECT * FROM clients WHERE id=?");
        $s->execute([$cid]);
        $client = $s->fetch();
        $s = db()->prepare(
            "SELECT a.*,s.name service,s.price,b.name barber FROM appointments a JOIN services s ON s.id=a.service_id LEFT JOIN barbers b ON b.id=a.barber_id WHERE a.client_id=? ORDER BY a.start_at DESC",
        );
        $s->execute([$cid]);
        $history = $s->fetchAll();
    }
    ?>
<div class="card"><form method="get"><label>Escolha o cliente</label><select name="client_id" onchange="this.form.submit()"><option value="">Selecione</option><?php foreach (
    db()->query("SELECT id,name,phone FROM clients ORDER BY name")
    as $c
): ?><option value="<?= $c["id"] ?>" <?= $cid == $c["id"]
    ? "selected"
    : "" ?>><?= e(
    $c["name"] . " - " . $c["phone"],
) ?></option><?php endforeach; ?></select></form></div><?php if (
    $client
): ?><div class="card"><h2><?= e(
    $client["name"],
) ?></h2><p><b>Telefone:</b> <?= e(
    $client["phone"],
) ?> · <b>Observação:</b> <?= e(
     $client["notes"],
 ) ?></p></div><div class="card table"><table><thead><tr><th>Data</th><th>Serviço</th><th>Barbeiro</th><th>Valor</th><th>Status</th></tr></thead><tbody><?php foreach (
    $history
    as $r
): ?><tr><td><?= date("d/m/Y H:i", strtotime($r["start_at"])) ?></td><td><?= e(
    $r["service"],
) ?></td><td><?= e($r["barber"]) ?></td><td><?= money(
    $r["price"],
) ?></td><td><?= e(
    $r["status"],
) ?></td></tr><?php endforeach; ?></tbody></table></div><?php endif; ?>
<?php
else:

    $rows = [];
    $clientList = [];
    $serviceList = [];
    $roleList = [];
    $barberList = [];
    if ($module === "appointments") {
        $rows = db()
            ->query(
                "SELECT a.*,c.name client,c.phone client_phone,s.name service,b.name barber FROM appointments a JOIN clients c ON c.id=a.client_id JOIN services s ON s.id=a.service_id LEFT JOIN barbers b ON b.id=a.barber_id ORDER BY start_at DESC",
            )
            ->fetchAll();
        $clientList = db()
            ->query("SELECT * FROM clients ORDER BY name")
            ->fetchAll();
        $serviceList = db()
            ->query("SELECT * FROM services WHERE active=1 ORDER BY name")
            ->fetchAll();
        $barberList = db()
            ->query("SELECT * FROM barbers WHERE active=1 ORDER BY name")
            ->fetchAll();
    } elseif ($module === "users") {
        $rows = db()
            ->query(
                "SELECT u.*,r.name role,r.permissions role_permissions,r.active role_active FROM users u JOIN roles r ON r.id=u.role_id ORDER BY u.name",
            )
            ->fetchAll();
        $roleList = db()
            ->query("SELECT * FROM roles WHERE active=1 ORDER BY name")
            ->fetchAll();
    } else {
        $rows = db()
            ->query("SELECT * FROM " . $tables[$module] . " ORDER BY id DESC")
            ->fetchAll();
    }
    $search = trim($_GET["search"] ?? "");
    if ($search !== "") {
        $rows = array_values(
            array_filter(
                $rows,
                fn($row) => stripos(
                    implode(" ", array_map("strval", $row)),
                    $search,
                ) !== false,
            ),
        );
    }
    ?><div class="actions"><span><?= count(
    $rows,
) ?> registro(s)</span><button onclick="openForm()">+ Novo</button></div>
<form class="search" method="get"><input name="search" value="<?= e(
    $search,
) ?>" placeholder="Pesquisar nesta aba..."><button>Pesquisar</button></form>
<?php if (
    $module === "roles"
): ?><div class="info-grid"><div class="info"><b>Administrador</b><span>Acesso total, incluindo funções, segurança, configurações e backups.</span></div><div class="info"><b>Gerente</b><span>Opera clientes, agenda, equipe, estoque e relatórios.</span></div><div class="info"><b>Barbeiro</b><span>Acessa clientes, históricos, agenda, serviços e profissionais.</span></div><div class="info"><b>Recepção</b><span>Organiza clientes, históricos, serviços, barbeiros e agendamentos.</span></div></div><div class="card permissions-help"><h2>O que cada permissão permite</h2><p><b>Clientes:</b> cadastrar, pesquisar, editar e excluir clientes.</p><p><b>Histórico:</b> consultar todos os atendimentos realizados por cliente.</p><p><b>Agenda:</b> criar, editar, concluir, cancelar e confirmar horários.</p><p><b>Serviços:</b> controlar preço, duração e disponibilidade.</p><p><b>Barbeiros:</b> cadastrar e editar os profissionais da equipe.</p><p><b>Relatórios:</b> consultar resultados e exportar dados para planilha.</p><p><b>Logins:</b> área exclusiva do Administrador.</p><p><b>Funções:</b> modificar perfis e permissões de acesso.</p><p><b>Backup:</b> baixar e restaurar todos os dados do sistema.</p><p><b>Configurações:</b> alterar dados da barbearia e expediente.</p><p><b>Segurança:</b> disponível a todos para troca da própria senha; o administrador também consulta atividades.</p></div><?php endif; ?>
<div class="card table"><table><thead><tr><?php if (
    $module === "clients"
): ?><th>Nome</th><th>Telefone</th><th>Observação</th><?php elseif (
    $module === "services"
): ?><th>Serviço</th><th>Preço</th><th>Duração</th><th>Status</th><?php elseif (
    $module === "appointments"
): ?><th>Data</th><th>Cliente</th><th>Serviço</th><th>Status</th><?php elseif (
    $module === "finance"
): ?><th>Data</th><th>Descrição</th><th>Tipo</th><th>Pagamento</th><th>Valor</th><?php elseif (
    $module === "users"
): ?><th>Usuário</th><th>Login</th><th>Cargo</th><th>Acessos do cargo</th><th>Cargo</th><th>Login</th><?php else: ?><th>Função</th><th>Permissões</th><th>Status</th><?php endif; ?><th>Ações</th></tr></thead><tbody><?php foreach (
    $rows
    as $r
): ?><tr><?php if ($module === "clients"): ?><td><b><?= e(
    $r["name"],
) ?></b></td><td><?= e($r["phone"]) ?></td><td><?= e(
    $r["notes"],
) ?></td><?php elseif ($module === "services"): ?><td><b><?= e(
    $r["name"],
) ?></b></td><td><?= money($r["price"]) ?></td><td><?= $r[
    "duration"
] ?> min</td><td><?= $r["active"] ? "Ativo" : "Inativo" ?></td><?php elseif (
    $module === "appointments"
): ?><td><?= date("d/m/Y H:i", strtotime($r["start_at"])) ?></td><td><?= e(
    $r["client"],
) ?></td><td><?= e($r["service"]) ?></td><td><span class="badge"><?= e(
    $r["status"],
) ?></span></td><?php elseif ($module === "finance"): ?><td><?= date(
    "d/m/Y",
    strtotime($r["date"]),
) ?></td><td><?= e($r["description"]) ?></td><td><?= e(
    $r["type"],
) ?></td><td><?= e($r["payment_method"] ?? "Dinheiro") ?></td><td><?= money(
    $r["amount"],
) ?></td><?php elseif ($module === "users"): ?><td><b><?= e(
    $r["name"],
) ?></b></td><td><code class="login-code"><?= e(
    $r["email"],
) ?></code></td><td><b><?= e(
    $r["role"],
) ?></b></td><td><div class="permission-chips"><?= permission_chips(
    $r["role_permissions"],
) ?></div></td><td><span class="role-status <?= $r["role_active"]
    ? "active"
    : "inactive" ?>"><?= $r["role_active"]
    ? "Ativo"
    : "Desativado" ?></span></td><td><span class="role-status <?= $r["active"]
    ? "active"
    : "inactive" ?>"><?= $r["active"]
    ? "Ativo"
    : "Desativado" ?></span></td><?php else: ?><td><div class="role-name"><span class="role-icon">♚</span><b><?= e(
    $r["name"],
) ?></b></div></td><td><div class="permission-chips"><?= permission_chips(
    $r["permissions"],
) ?></div></td><td><span class="role-status <?= $r["active"]
    ? "active"
    : "inactive" ?>"><?= $r["active"]
    ? "Ativo"
    : "Desativado" ?></span></td><?php endif; ?><td><a class="edit" href="<?= $files[
    $module
] ?>?edit=<?= $r[
    "id"
] ?>">Editar</a> <a class="del" onclick="return confirm('Excluir registro?')" href="<?= $files[
    $module
] ?>?delete=<?= $r[
    "id"
] ?>">Excluir</a></td></tr><?php endforeach; ?></tbody></table></div>
<div class="modal <?= !empty($edit)
    ? "show"
    : "" ?>" id="modal"><form method="post" class="form"><a class="x" href="<?= $files[
    $module
] ?>">×</a><h2><?= empty($edit)
    ? "Novo registro"
    : "Editar registro" ?></h2><input type="hidden" name="id" value="<?= e(
    $edit["id"] ?? 0,
) ?>">
<?php if ($module === "clients"):

    echo field("name", "Nome", "text", $edit["name"] ?? "");
    echo field("phone", "Telefone", "text", $edit["phone"] ?? "");
    echo field("notes", "Observação", "text", $edit["notes"] ?? "", false);
    ?>
<?php
elseif ($module === "services"):

    echo field("name", "Serviço", "text", $edit["name"] ?? "");
    echo field("price", "Preço", "number", $edit["price"] ?? "");
    echo field("duration", "Duração em minutos", "number", $edit["duration"] ?? "");
    ?> <label><input class="auto" type="checkbox" name="active" <?= !isset(
     $edit["active"],
 ) || $edit["active"]
     ? "checked"
     : "" ?>> Serviço ativo</label>
<?php
elseif (
    $module === "appointments"
): ?><label>Cliente</label><select name="client_id" required><?php foreach (
    $clientList
    as $x
): ?><option value="<?= $x["id"] ?>" <?= ($edit["client_id"] ?? 0) == $x["id"]
    ? "selected"
    : "" ?>><?= e(
    $x["name"],
) ?></option><?php endforeach; ?></select><label>Serviço</label><select name="service_id"><?php foreach (
    $serviceList
    as $x
): ?><option value="<?= $x["id"] ?>" <?= ($edit["service_id"] ?? 0) == $x["id"]
    ? "selected"
    : "" ?>><?= e($x["name"]) ?></option><?php endforeach; ?></select><?=
field(
    "date",
    "Data",
    "date",
    isset($edit["start_at"])
        ? date("Y-m-d", strtotime($edit["start_at"]))
        : date("Y-m-d"),
)
. field(
    "time",
    "Hora",
    "time",
    isset($edit["start_at"]) ? date("H:i", strtotime($edit["start_at"])) : "",
)
?> <label>Status</label><select name="status"><?php foreach (
     ["Pendente", "Confirmado", "Concluído", "Cancelado"]
     as $x
 ): ?><option <?= ($edit["status"] ?? "Pendente") === $x
    ? "selected"
    : "" ?>><?= $x ?></option><?php endforeach; ?></select><?= field(
    "notes",
    "Observação",
    "text",
    $edit["notes"] ?? "",
    false,
) ?>
<?php elseif (
    $module === "finance"
): ?><label>Tipo</label><select name="type"><option <?= ($edit["type"] ??
    "") ===
"Receita"
    ? "selected"
    : "" ?>>Receita</option><option <?= ($edit["type"] ?? "") === "Despesa"
    ? "selected"
    : "" ?>>Despesa</option></select><?=
field("description", "Descrição", "text", $edit["description"] ?? "")
. field("amount", "Valor", "number", $edit["amount"] ?? "")
. field("date", "Data", "date", $edit["date"] ?? date("Y-m-d"))
?><label>Forma de pagamento</label><select name="payment_method"><option>Dinheiro</option><option <?= ($edit[
    "payment_method"
] ??
    "") ===
"Pix"
    ? "selected"
    : "" ?>>Pix</option><option <?= ($edit["payment_method"] ?? "") === "Cartão"
    ? "selected"
    : "" ?>>Cartão</option><option <?= ($edit["payment_method"] ?? "") ===
"Outro"
    ? "selected"
    : "" ?>>Outro</option></select><label>Status</label><select name="status"><option>Pago</option><option <?= ($edit[
    "status"
] ??
    "") ===
"Pendente"
    ? "selected"
    : "" ?>>Pendente</option></select>
<?php elseif ($module === "users"):

    $professionalName = "";
    if (!empty($edit["id"])) {
        $ps = db()->prepare("SELECT name FROM barbers WHERE user_id=?");
        $ps->execute([$edit["id"]]);
        $professionalName = (string) $ps->fetchColumn();
    }
    echo field("name", "Nome do usuário", "text", $edit["name"] ?? "");
    echo field(
        "professional_name",
        "Nome profissional mostrado aos clientes",
        "text",
        $professionalName,
        false,
    );
    ?><small class="field-help">Esse será o nome disponível para o cliente escolher no agendamento.</small><?=
field("login", "Login de acesso", "text", $edit["email"] ?? "")
. field(
    "password",
    empty($edit) ? "Senha" : "Nova senha (deixe vazio para manter)",
    "password",
    "",
    empty($edit),
)
?><label>Função</label><select name="role_id"><?php foreach (
    $roleList
    as $x
): ?><option value="<?= $x["id"] ?>" <?= ($edit["role_id"] ?? 0) == $x["id"]
    ? "selected"
    : "" ?>><?= e(
    $x["name"],
) ?></option><?php endforeach; ?></select><label><input class="auto" type="checkbox" name="active" <?= !isset(
    $edit["active"],
) || $edit["active"]
    ? "checked"
    : "" ?>> Login e profissional ativos</label>
<?php
else:

    echo field("name", "Nome da função", "text", $edit["name"] ?? "");
    $selected = explode(",", $edit["permissions"] ?? "");
    ?><div class="permission-heading"><div><b>Permissões do cargo</b><small>Escolha o que este cargo pode visualizar ou alterar.</small></div><div class="permission-actions"><button type="button" onclick="setPermissionMode('view')">Somente visualizar</button><button type="button" onclick="setPermissionMode('all')">Acesso completo</button><button type="button" onclick="setPermissionMode('none')">Limpar</button></div></div><?php foreach (
    [
        "clients" => "Clientes",
        "appointments" => "Agenda",
        "services" => "Serviços",
        "barbers" => "Barbeiros",
        "inventory" => "Estoque",
        "roles" => "Funções e permissões",
        "backups" => "Backup e restauração",
        "settings" => "Configurações",
    ]
    as $k => $v
): ?><div class="permission-row"><b><?= $v ?></b><label><input class="auto" type="checkbox" name="permissions[]" value="<?= $k ?>.view" <?= in_array(
    $k . ".view",
    $selected,
) || in_array($k, $selected)
    ? "checked"
    : "" ?>> Visualizar</label><label><input class="auto" type="checkbox" name="permissions[]" value="<?= $k ?>.manage" <?= in_array(
    $k . ".manage",
    $selected,
) || in_array($k, $selected)
    ? "checked"
    : "" ?>> Editar</label></div><?php endforeach; ?><div class="permission-row"><b>Histórico</b><label><input class="auto" type="checkbox" name="permissions[]" value="history.view" <?= in_array(
    "history.view",
    $selected,
) || in_array("history", $selected)
    ? "checked"
    : "" ?>> Visualizar</label></div><div class="permission-row"><b>Relatórios</b><label><input class="auto" type="checkbox" name="permissions[]" value="reports.view" <?= in_array(
    "reports.view",
    $selected,
) || in_array("reports", $selected)
    ? "checked"
    : "" ?>> Visualizar</label><label><input class="auto" type="checkbox" name="permissions[]" value="reports.export" <?= in_array(
    "reports.export",
    $selected,
) || in_array("reports", $selected)
    ? "checked"
    : "" ?>> Exportar</label></div><label><input class="auto" type="checkbox" name="active" <?= !isset(
    $edit["active"],
) || $edit["active"]
    ? "checked"
    : "" ?>> Cargo ativo</label><?php
endif; ?><button>Salvar</button></form></div><?php
endif; ?></section></main><script>document.querySelectorAll('form[method="post"]').forEach(f=>{if(!f.querySelector('input[name="csrf"]')){let i=document.createElement('input');i.type='hidden';i.name='csrf';i.value='<?= csrf_token() ?>';f.appendChild(i)}});document.querySelectorAll('a[href*="delete="]').forEach(a=>{a.href+=(a.href.includes('?')?'&':'?')+'csrf=<?= csrf_token() ?>'});function toggleUserMenu(event){event.stopPropagation();document.getElementById('userDropdown').classList.toggle('show')}document.addEventListener('click',()=>{let menu=document.getElementById('userDropdown');if(menu)menu.classList.remove('show')});function openForm(){modal.classList.add('show')}function setPermissionMode(mode){document.querySelectorAll('.permission-row input[type=checkbox]').forEach(input=>{if(mode==='all')input.checked=true;else if(mode==='view')input.checked=input.value.endsWith('.view');else input.checked=false})}document.addEventListener('change',e=>{if(!e.target.matches('.permission-row input[type=checkbox]'))return;let value=e.target.value;if(value.endsWith('.manage')&&e.target.checked){let view=document.querySelector('input[value="'+value.replace('.manage','.view')+'"]');if(view)view.checked=true}if(value.endsWith('.view')&&!e.target.checked){let manage=document.querySelector('input[value="'+value.replace('.view','.manage')+'"]');if(manage)manage.checked=false}});<?php
if (
    !$canManage &&
    $module !== "security"
): ?>document.querySelectorAll('.actions button,.edit,.del,.modal,form[method="post"]:not(.search)').forEach(e=>e.style.display='none');<?php endif;
if (
    $module === "reports" &&
    !has_perm("reports.export")
): ?>document.querySelectorAll('a[href*="export=1"]').forEach(e=>e.style.display='none');<?php endif;
?></script><script>
let knownNotificationMax=0,originalTitle=document.title,audioReady=false;
document.addEventListener('click',()=>audioReady=true,{once:true});
function notificationSound(){if(!audioReady)return;try{let a=new(window.AudioContext||window.webkitAudioContext),o=a.createOscillator(),g=a.createGain();o.connect(g);g.connect(a.destination);o.frequency.value=880;g.gain.setValueAtTime(.12,a.currentTime);g.gain.exponentialRampToValueAtTime(.001,a.currentTime+.45);o.start();o.stop(a.currentTime+.45)}catch(e){}}
async function loadNotifications(){try{let r=await fetch('notificacoes.php',{cache:'no-store'}),d=await r.json(),count=document.getElementById('notificationCount'),list=document.getElementById('notificationList');count.textContent=d.count||'';count.classList.toggle('show',d.count>0);document.title=d.count?'('+d.count+') '+originalTitle:originalTitle;if(d.items.length){list.innerHTML=d.items.map(x=>`<a href="agenda.php?edit=${x.id}" onclick="return openNotification(event,${x.id},this.href)"><b>${x.client}</b><span>${x.service} com ${x.barber}</span><small>${x.when}</small></a>`).join('');let newest=Math.max(...d.items.map(x=>Number(x.id)));if(knownNotificationMax&&newest>knownNotificationMax){notificationSound();document.getElementById('bookingToastText').textContent=d.items[0].client+' marcou '+d.items[0].service;document.getElementById('bookingToast').classList.add('show')}knownNotificationMax=newest}else{list.innerHTML='<p class="notification-empty">Nenhum agendamento novo.</p>';knownNotificationMax=0}}catch(e){}}
function toggleNotifications(event){event.stopPropagation();document.getElementById('notificationPanel').classList.toggle('show')}async function openNotification(event,id,url){event.preventDefault();event.stopPropagation();await fetch('notificacoes.php',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:'csrf=<?= csrf_token() ?>&appointment_id='+encodeURIComponent(id)});location.href=url;return false}
document.addEventListener('click',()=>document.getElementById('notificationPanel')?.classList.remove('show'));
loadNotifications();setInterval(loadNotifications,10000);
</script></body></html>
<?php function field($name, $label, $type, $value, $required = true)
{
    return "<label>" .
        e($label) .
        '</label><input type="' .
        $type .
        '" step="0.01" name="' .
        $name .
        '" value="' .
        e($value) .
        '" ' .
        ($required ? "required" : "") .
        ">";
}
