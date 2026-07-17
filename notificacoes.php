<?php
declare(strict_types=1);
session_set_cookie_params(['httponly'=>true,'samesite'=>'Lax']);
session_start();
require __DIR__.'/database.php';
header('Content-Type: application/json; charset=utf-8');
if(empty($_SESSION['user']['id'])){http_response_code(401);echo json_encode(['count'=>0,'items'=>[]]);exit;}
$userId=(int)$_SESSION['user']['id'];
if($_SERVER['REQUEST_METHOD']==='POST'){
    if(!hash_equals($_SESSION['csrf']??'',$_POST['csrf']??'')){http_response_code(403);exit;}
    $appointmentId=(int)($_POST['appointment_id']??0);
    if($appointmentId>0)db()->prepare('INSERT IGNORE INTO notification_reads(user_id,appointment_id) VALUES(?,?)')->execute([$userId,$appointmentId]);
    echo json_encode(['ok'=>true]);exit;
}
$s=db()->prepare("SELECT a.id,c.name client,s.name service,COALESCE(b.name,'Sem profissional') barber,a.start_at
 FROM appointments a JOIN clients c ON c.id=a.client_id JOIN services s ON s.id=a.service_id LEFT JOIN barbers b ON b.id=a.barber_id
 WHERE a.notes='Agendamento realizado pelo cliente no site'
 AND NOT EXISTS(SELECT 1 FROM notification_reads nr WHERE nr.user_id=? AND nr.appointment_id=a.id)
 ORDER BY a.id DESC LIMIT 10");
$s->execute([$userId]);$items=[];
foreach($s as $r)$items[]=['id'=>(int)$r['id'],'client'=>$r['client'],'service'=>$r['service'],'barber'=>$r['barber'],'when'=>date('d/m/Y H:i',strtotime($r['start_at']))];
echo json_encode(['count'=>count($items),'items'=>$items],JSON_UNESCAPED_UNICODE);
