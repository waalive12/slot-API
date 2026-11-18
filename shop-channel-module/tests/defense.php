<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/Core.php';require dirname(__DIR__).'/src/Defense.php';
$n=0;function ok(bool $v,string $s):void{global $n;if(!$v)throw new RuntimeException($s);$n++;echo "PASS $s\n";}
function rejects(callable $f,string $s):void{try{$f();}catch(InvalidArgumentException $e){ok(true,$s);return;}ok(false,$s);}
$c=new Shop\Core(':memory:');$d=new Shop\Defense($c);$now=time();$sub=str_repeat('a',64);
$d->import([['scope'=>'login','cidr'=>'192.0.2.5/24','expires_at'=>$now+60],['scope'=>'coupon','cidr'=>'2001:db8::/32','expires_at'=>$now+60]]);
ok($d->guard('login',$sub,'192.0.2.8',$now)['status']===403,'v4 blocked only at guarded operation');
ok($d->guard('login',$sub,'::ffff:192.0.2.8',$now)['status']===403,'mapped v4 cannot bypass');
ok($d->guard('register',$sub,'192.0.2.8',$now)['status']===200,'scope isolation');
ok($d->guard('coupon',$sub,'2001:db8:abcd::1',$now)['status']===403,'v6 blocked');
ok($d->guard('login',$sub,'192.0.2.8',$now+61)['status']===200,'expired deny ignored');
rejects(fn()=>$d->guard('landing',$sub,'192.0.2.8',$now),'landing guard forbidden');
rejects(fn()=>$d->import([['scope'=>'all','cidr'=>'192.0.2.0/24','expires_at'=>$now+60]]),'generic scope rejected');
rejects(fn()=>$d->guard('login',$sub,'forged-ip',$now),'invalid IP rejected');
rejects(fn()=>$d->import([['scope'=>'login','cidr'=>'203.0.113.0/24','expires_at'=>$now+60],['scope'=>'landing','cidr'=>'::/0','expires_at'=>$now+60]]),'import all or nothing');ok(count($d->list())===2,'no partial import');
$id=(int)$d->list()[0]['id'];ok($d->update($id,['scope'=>'login','cidr'=>'198.51.100.1','expires_at'=>$now+120]),'edit existing entry');ok($d->guard('login',$sub,'192.0.2.8',$now)['status']===200,'old address released');ok($d->guard('login',$sub,'198.51.100.1',$now)['status']===403,'new address guarded');ok($d->delete($id),'delete entry');ok(!$d->delete($id),'missing delete false');ok($d->guard('login',$sub,'198.51.100.1',$now)['status']===200,'delete releases');
$c->setRate('register','limit',1,60);ok($d->guard('register',$sub,'203.0.113.1',$now)['status']===200,'rate guard first allowed');ok($d->guard('register',$sub,'203.0.113.1',$now)['status']===429,'rate guard second limited');
ok((int)$c->run("SELECT count(*) FROM audit WHERE action LIKE 'operation_denies.%'")->fetchColumn()===3,'deny mutations audited');rejects(fn()=>$d->import([['scope'=>'login','cidr'=>'0.0.0.0/0','expires_at'=>$now+60]]),'v4 all-address deny rejected');
rejects(fn()=>$d->import([['scope'=>'login','cidr'=>'::/0','expires_at'=>$now+60]]),'v6 all-address deny rejected');
rejects(fn()=>$d->import([['scope'=>'login','cidr'=>'::ffff:0.0.0.0/96','expires_at'=>$now+60]]),'mapped all-address deny rejected');
echo "$n assertions passed\n";
