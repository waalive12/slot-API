<?php
declare(strict_types=1);
require __DIR__.'/../src/Core.php';
require __DIR__.'/../src/Channels.php';
$core = new Shop\Core(':memory:');
$channels = new Shop\Channels($core->db);
$count = 0;
function check(bool $pass): void { global $count; if (!$pass) { throw new RuntimeException('Assertion failed at '.($count+1)); } $count++; }
$channels->bind('shop-br','spring');
$channels->bind('shop-br','collection');
$channels->bind('shop-am','spring');
$channels->configure('shop-br','spring','email','/products/coffee',true);
$channels->configure('shop-br','collection','email','/collections/summer',true);
$channels->configure('shop-am','spring','email','/',true);
check(count($channels->list('shop-br'))===2);
check(count($channels->list('shop-am'))===1);
check($channels->resolve('shop-br','spring','email')==='/products/coffee');
check($channels->resolve('shop-br','collection','email')==='/collections/summer');
check($channels->resolve('shop-am','spring','email')==='/');
check($channels->resolve('shop-br','spring','unknown')===null);
foreach (['https://other.test/','//other.test/','/products/../other','/products/a?x=b','/login',"/products/a\r\nLocation:x",'/products/%2f%2fother'] as $invalid) {
    try { Shop\Channels::destination($invalid); check(false); }
    catch (InvalidArgumentException) { check(true); }
}
try { $channels->configure('shop-br','not-bound','email','/',true); check(false); }
catch (InvalidArgumentException) { check(true); }
$channels->configure('shop-br','spring','email','/',false);
check($channels->resolve('shop-br','spring','email')===null);
check($channels->resolve('shop-am','spring','email')==='/');
check((int)$core->run("SELECT COUNT(*) FROM audit WHERE action LIKE 'channels.%'")->fetchColumn()===7);
echo "$count channel assertions passed\n";
