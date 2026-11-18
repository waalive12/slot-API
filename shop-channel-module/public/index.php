<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/Core.php';
require dirname(__DIR__).'/src/Defense.php';
require dirname(__DIR__).'/src/Channels.php';
header('Content-Type: application/json; charset=utf-8');header('Cache-Control: no-store');header('X-Content-Type-Options: nosniff');
function respond(int $status,array $data):never{http_response_code($status);echo json_encode($data,JSON_THROW_ON_ERROR|JSON_UNESCAPED_UNICODE);exit;}
function auth(string $env):void {
 $token=getenv($env);$admin=getenv('SHOP_ADMIN_TOKEN');$integration=getenv('SHOP_INTEGRATION_TOKEN');if(!$admin||!$integration||strlen($admin)<32||strlen($integration)<32||hash_equals($admin,$integration))respond(503,['error'=>'Distinct service credentials required']);if(!$token||strlen($token)<32)respond(503,['error'=>'Service credentials not configured']);
 if(!hash_equals('Bearer '.$token,$_SERVER['HTTP_AUTHORIZATION']??''))respond(401,['error'=>'Unauthorized']);
}
function body():array{if(stripos($_SERVER['CONTENT_TYPE']??'','application/json')!==0)respond(415,['error'=>'application/json required']);$raw=file_get_contents('php://input',false,null,0,65537);if(strlen($raw)>65536)respond(413,['error'=>'Body too large']);$data=json_decode($raw,true,32,JSON_THROW_ON_ERROR);if(!is_array($data))throw new InvalidArgumentException('JSON object required');return $data;}
function field(array $b,string $k,string $type):mixed{if(!array_key_exists($k,$b)||gettype($b[$k])!==$type)throw new InvalidArgumentException('Invalid field: '.$k);return $b[$k];}
try{
 $uri=$_SERVER['REQUEST_URI'];
 $path=parse_url($uri,PHP_URL_PATH);$method=$_SERVER['REQUEST_METHOD'];
 if(!is_string($path)||!str_starts_with($uri,'/')||str_starts_with($uri,'//'))respond(400,['error'=>'Invalid request path']);
 $dbpath=getenv('SHOP_DB')?:dirname(__DIR__).'/var/shop.sqlite';
 if(in_array($method,['GET','HEAD'],true)&&preg_match('~^/go/([a-z0-9-]{1,48})/([a-z0-9-]{1,48})/([a-z0-9-]{1,48})$~D',$path,$m)){
  $target=(new Shop\Channels((new Shop\Core($dbpath))->db))->resolve($m[1],$m[2],$m[3]);
  if($target===null)respond(404,['error'=>'Channel not found']);
  header('Location: '.$target,true,302);exit;
 }
 if($path==='/'&&$method==='GET')respond(200,['service'=>'Shop safety module','public_landing'=>'Identical for all visitors','version'=>'1.0.0']);
 $admin=str_starts_with($path,'/admin/');$internal=str_starts_with($path,'/internal/');
 if(!$admin&&!$internal)respond(404,['error'=>'Not found']);
 auth($admin?'SHOP_ADMIN_TOKEN':'SHOP_INTEGRATION_TOKEN');
 $core=new Shop\Core($dbpath);
 if($admin&&!$core->adminAllowed($_SERVER['REMOTE_ADDR']??'',time()))respond(403,['error'=>'Admin network not permitted']);
 // X-Forwarded-For, CF-Connecting-IP and User-Agent are intentionally ignored.
 if($admin&&str_starts_with($path,'/admin/channels')){
  $channels=new Shop\Channels($core->db);
  if($path==='/admin/channels/bindings'&&$method==='PUT'){$b=body();$channels->bind(field($b,'site','string'),field($b,'project','string'));respond(200,['saved'=>true]);}
  if($path==='/admin/channels/links'&&$method==='PUT'){$b=body();$channels->configure(field($b,'site','string'),field($b,'project','string'),field($b,'channel','string'),field($b,'destination','string'),field($b,'active','boolean'));respond(200,['saved'=>true]);}
  if($path==='/admin/channels/links'&&$method==='GET')respond(200,['links'=>$channels->list(field($_GET,'site','string'))]);
 }
 if($path==='/admin/operation-denies'&&$method==='GET')respond(200,['entries'=>(new Shop\Defense($core))->list()]);
 if($path==='/admin/operation-denies'&&$method==='POST'){$b=body();respond(200,['imported'=>(new Shop\Defense($core))->import(field($b,'entries','array'))]);}
 if(preg_match('#^/admin/operation-denies/([1-9][0-9]*)$#D',$path,$m)&&in_array($method,['PUT','DELETE'],true)){$d=new Shop\Defense($core);$ok=$method==='PUT'?$d->update((int)$m[1],body()):$d->delete((int)$m[1]);respond($ok?200:404,[$ok?'saved':'error'=>$ok?true:'Entry not found']);}
 if($path==='/admin/networks'&&$method==='GET')respond(200,['entries'=>$core->run('SELECT * FROM admin_networks ORDER BY id')->fetchAll(PDO::FETCH_ASSOC)]);
 if($path==='/admin/networks'&&$method==='POST'){$b=body();respond(200,['imported'=>$core->importNetworks(field($b,'entries','array'))]);}
 if(preg_match('#^/admin/networks/([1-9][0-9]*)$#D',$path,$m)&&$method==='DELETE'){$core->deleteNetwork((int)$m[1]);respond(200,['deleted'=>(int)$m[1]]);}
 if($path==='/admin/rates'&&$method==='GET')respond(200,['policies'=>$core->run('SELECT * FROM rates')->fetchAll(PDO::FETCH_ASSOC)]);
 if($path==='/admin/rates'&&$method==='PUT'){$b=body();$core->setRate(field($b,'scope','string'),field($b,'mode','string'),field($b,'max_hits','integer'),field($b,'window_seconds','integer'));respond(200,['saved'=>true]);}
 if($path==='/admin/products'&&$method==='GET')respond(200,['products'=>$core->run('SELECT * FROM products')->fetchAll(PDO::FETCH_ASSOC)]);
 if($path==='/admin/products'&&$method==='PUT'){$b=body();$core->setProduct(field($b,'product','string'),field($b,'countries','array'));respond(200,['saved'=>true]);}
 if($path==='/admin/audit'&&$method==='GET')respond(200,['events'=>$core->run('SELECT * FROM audit ORDER BY id DESC LIMIT 100')->fetchAll(PDO::FETCH_ASSOC)]);
 if($path==='/internal/rate/consume'&&$method==='POST'){$b=body();if(array_diff(array_keys($b),['scope','subject','client_ip']))throw new InvalidArgumentException('Unsupported guard fields');$r=(new Shop\Defense($core))->guard(field($b,'scope','string'),field($b,'subject','string'),field($b,'client_ip','string'),time());if($r['status']===429)header('Retry-After: '.$r['retry_after']);respond($r['status'],$r);}
 if($path==='/internal/shipping/check'&&$method==='POST'){$b=body();respond(200,$core->eligibility(field($b,'product','string'),field($b,'shipping_country','string')));}
 respond(404,['error'=>'Not found']);
}catch(InvalidArgumentException|JsonException $e){respond(400,['error'=>$e->getMessage()]);}catch(Throwable $e){error_log('Shop module failure: '.get_class($e));respond(503,['error'=>'Service temporarily unavailable']);}
