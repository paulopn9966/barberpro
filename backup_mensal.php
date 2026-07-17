<?php
declare(strict_types=1);
if(PHP_SAPI!=='cli'){http_response_code(403);exit('Acesso permitido somente pelo agendador do sistema.');}
require __DIR__.'/database.php';
$folder='C:\\xampp\\barberpro-backups';
if(!is_dir($folder)&&!mkdir($folder,0755,true))exit(1);
$month=date('Y-m');$file=$folder.'\\barberpro-'.$month.'.sql';
$tables=db()->query('SHOW TABLES')->fetchAll(PDO::FETCH_COLUMN);
$sql="SET FOREIGN_KEY_CHECKS=0;\nCREATE DATABASE IF NOT EXISTS barbearia_system CHARACTER SET utf8mb4;\nUSE barbearia_system;\n";
foreach($tables as $table){$create=db()->query("SHOW CREATE TABLE `$table`")->fetch();$sql.="DROP TABLE IF EXISTS `$table`;\n".$create['Create Table'].";\n";foreach(db()->query("SELECT * FROM `$table`") as $row){$values=array_map(fn($v)=>$v===null?'NULL':db()->quote((string)$v),array_values($row));$sql.="INSERT INTO `$table` VALUES(".implode(',',$values).");\n";}}
$sql.="SET FOREIGN_KEY_CHECKS=1;\n";
file_put_contents($file,$sql,LOCK_EX);
$s=db()->prepare("INSERT INTO settings(setting_key,setting_value) VALUES('backup_last_month',?) ON DUPLICATE KEY UPDATE setting_value=VALUES(setting_value)");$s->execute([$month]);
$backups=glob($folder.'\\barberpro-*.sql')?:[];usort($backups,fn($a,$b)=>filemtime($b)<=>filemtime($a));foreach(array_slice($backups,12) as $old){$real=realpath($old);if($real&&str_starts_with(strtolower($real),strtolower($folder.'\\')))unlink($real);}
echo "Backup mensal criado: $file\n";
