<?php
declare(strict_types=1);
require dirname(__DIR__).'/src/Core.php';
$n=0;function ok(bool $v,string $s):void{global $n;if(!$v)throw new RuntimeException($s);$n++;echo "PASS $s\n";}
function rejects(callable $f,string $s):void{try{$f();}catch(InvalidArgumentException $e){ok(true,$s);return;}ok(false,$s);}
$c=new Shop\Core(':memory:');
ok(Shop\Core::network('192.0.2.123/24')[0]==='192.0.2.0/24','canonical v4');
ok(Shop\Core::network('2001:db8::123/64')[0]==='2001:db8::/64','canonical v6');
ok(Shop\Core::contains('2001:db8::/32','2001:db8:abcd::1'),'v6 match');
ok(!Shop\Core::contains('192.0.2.0/24','192.0.3.1'),'v4 reject');
ok(!Shop\Core::contains('0.0.0.0/0','::1'),'address families isolated');
rejects(fn()=>Shop\Core::network('1.2.3.4/33'),'bad v4 prefix');rejects(fn()=>Shop\Core::network('::/129'),'bad v6 prefix');rejects(fn()=>Shop\Core::network('10.0.0.1/abc'),'bad prefix text');
ok(!$c->adminAllowed('192.0.2.1',time()),'admin default deny');ok($c->adminAllowed('::1',time()),'loopback recovery network');
$c->importNetworks([['cidr'=>'192.0.2.1/24','expires_at'=>time()+60]]);ok($c->adminAllowed('192.0.2.3',time()),'allow imported network');ok(!$c->adminAllowed('192.0.2.3',time()+61),'expiry denies');
rejects(fn()=>$c->importNetworks([['cidr'=>'198.51.100.0/24','expires_at'=>time()+60],['cidr'=>'bad','expires_at'=>time()+60]]),'atomic validation');ok(!$c->adminAllowed('198.51.100.1',time()),'failed import not partial');
$c->deleteNetwork(1);ok(!$c->adminAllowed('192.0.2.1',time()),'delete revokes');
$s=hash('sha256','test');$c->setRate('login','limit',2,60);ok($c->consume('login',$s,120)['allowed'],'first hit');ok($c->consume('login',$s,121)['allowed'],'second hit');ok(!$c->consume('login',$s,122)['allowed'],'third rate limited');ok($c->consume('login',$s,180)['allowed'],'window resets');
$c->setRate('login','observe',1,60);$c->consume('login',$s,240);$r=$c->consume('login',$s,241);ok($r['allowed']&&$r['would_limit'],'observe does not block');rejects(fn()=>$c->consume('landing',$s,240),'no public landing scope');
$c->setProduct('sku1',['BR','AM']);ok($c->eligibility('sku1','BR')['allowed'],'supported destination');ok(!$c->eligibility('sku1','US')['allowed'],'unsupported destination');ok(!$c->eligibility('unknown','BR')['allowed'],'unconfigured product fails closed');ok((int)$c->run('SELECT count(*) FROM audit')->fetchColumn()===5,'audit records changes');echo "$n assertions passed\n";
