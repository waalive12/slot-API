<?php
declare(strict_types=1);
namespace Shop;
final class Core {
 public \PDO $db;
 public function __construct(string $file) {
  $this->db=new \PDO('sqlite:'.$file,null,null,[\PDO::ATTR_ERRMODE=>\PDO::ERRMODE_EXCEPTION]);
  $this->db->exec('PRAGMA busy_timeout=5000; PRAGMA journal_mode=WAL;
   CREATE TABLE IF NOT EXISTS admin_networks(id INTEGER PRIMARY KEY, cidr TEXT NOT NULL UNIQUE, expires INTEGER NOT NULL, note TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS rates(scope TEXT PRIMARY KEY, mode TEXT NOT NULL, max_hits INTEGER NOT NULL, window_seconds INTEGER NOT NULL);
   CREATE TABLE IF NOT EXISTS counters(scope TEXT NOT NULL, subject TEXT NOT NULL, bucket INTEGER NOT NULL, hits INTEGER NOT NULL, expires INTEGER NOT NULL, PRIMARY KEY(scope,subject,bucket));
   CREATE TABLE IF NOT EXISTS products(product TEXT PRIMARY KEY, countries TEXT NOT NULL);
   CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, ts INTEGER NOT NULL, action TEXT NOT NULL, detail TEXT NOT NULL);');
  foreach(['login','register','coupon'] as $s) $this->run('INSERT OR IGNORE INTO rates VALUES(?,?,?,?)',[$s,'observe',20,60]);
 }
 public function run(string $sql,array $args=[]): \PDOStatement { $q=$this->db->prepare($sql);$q->execute($args);return $q; }
 public static function network(string $input): array {
  $p=explode('/',$input); if(count($p)>2 || $p[0]==='' || !filter_var($p[0],FILTER_VALIDATE_IP)) throw new \InvalidArgumentException('Invalid IPv4/IPv6');
  $bytes=inet_pton($p[0]);$bits=strlen($bytes)*8;$prefix=$bits;
  if(isset($p[1])) { if(!preg_match('/^(0|[1-9][0-9]*)$/D',$p[1]) || (int)$p[1]>$bits) throw new \InvalidArgumentException('Invalid prefix'); $prefix=(int)$p[1]; }
  $masked='';for($i=0;$i<strlen($bytes);$i++){ $n=max(0,min(8,$prefix-$i*8));$masked.=chr(ord($bytes[$i]) & ($n===0?0:(255 << (8-$n)))); }
  return [inet_ntop($masked).'/'.$prefix,$masked,$prefix];
 }
 public static function contains(string $cidr,string $ip): bool {
  if(!filter_var($ip,FILTER_VALIDATE_IP)) return false;
  [, $net,$prefix]=self::network($cidr);$addr=inet_pton($ip);if(strlen($net)!==strlen($addr))return false;
  [, $masked]=self::network($ip.'/'.$prefix);return hash_equals($net,$masked);
 }
 public function adminAllowed(string $ip,int $now): bool {
  // Loopback is recovery access only; admin token remains mandatory at HTTP boundary.
  if($ip==='127.0.0.1'||$ip==='::1')return true;
  foreach($this->run('SELECT cidr FROM admin_networks WHERE expires>?',[$now])->fetchAll(\PDO::FETCH_COLUMN) as $c)if(self::contains($c,$ip))return true;
  return false;
 }
 private function audit(string $action,array $detail):void { $this->run('INSERT INTO audit(ts,action,detail) VALUES(?,?,?)',[time(),$action,json_encode($detail,JSON_THROW_ON_ERROR)]); }
 public function importNetworks(array $rows):int {
  if(!array_is_list($rows)||count($rows)<1||count($rows)>500)throw new \InvalidArgumentException('Supply 1–500 entries');
  $validated=[];foreach($rows as $r){if(!is_array($r)||!isset($r['cidr'],$r['expires_at'])||!is_string($r['cidr'])||!is_int($r['expires_at']))throw new \InvalidArgumentException('cidr and integer expires_at required');
   $expires=$r['expires_at'];if($expires<=time()||$expires>time()+366*86400)throw new \InvalidArgumentException('Expiry must be within next 366 days');
   $note=$r['note']??'';if(!is_string($note)||strlen($note)>250)throw new \InvalidArgumentException('note too long');
   $validated[]=[self::network($r['cidr'])[0],$expires,$note];}
  $this->db->beginTransaction();try{foreach($validated as $v)$this->run('INSERT INTO admin_networks(cidr,expires,note) VALUES(?,?,?) ON CONFLICT(cidr) DO UPDATE SET expires=excluded.expires,note=excluded.note',$v);$this->audit('admin_networks.import',['count'=>count($validated),'cidrs'=>array_column($validated,0)]);$this->db->commit();}catch(\Throwable $e){$this->db->rollBack();throw $e;}return count($validated);
 }
 public function deleteNetwork(int $id):void {$this->db->beginTransaction();try{$this->run('DELETE FROM admin_networks WHERE id=?',[$id]);$this->audit('admin_networks.delete',['id'=>$id]);$this->db->commit();}catch(\Throwable $e){$this->db->rollBack();throw $e;}}
 public function setRate(string $scope,string $mode,int $max,int $seconds):void {
  if(!in_array($scope,['login','register','coupon'],true)||!in_array($mode,['observe','limit'],true)||$max<1||$max>10000||$seconds<1||$seconds>3600)throw new \InvalidArgumentException('Invalid rate policy');
  $this->db->beginTransaction();try{$this->run('UPDATE rates SET mode=?,max_hits=?,window_seconds=? WHERE scope=?',[$mode,$max,$seconds,$scope]);$this->run('DELETE FROM counters WHERE scope=?',[$scope]);$this->audit('rates.update',compact('scope','mode','max','seconds'));$this->db->commit();}catch(\Throwable $e){$this->db->rollBack();throw $e;}
 }
 public function consume(string $scope,string $subject,int $now):array {
  if(!in_array($scope,['login','register','coupon'],true)||!preg_match('/^[a-f0-9]{64}$/D',$subject))throw new \InvalidArgumentException('Invalid scope or pseudonymous subject');
  $this->db->exec('BEGIN IMMEDIATE');try{
   $r=$this->run('SELECT * FROM rates WHERE scope=?',[$scope])->fetch(\PDO::FETCH_ASSOC);$w=(int)$r['window_seconds'];$bucket=intdiv($now,$w);$end=($bucket+1)*$w;
   $this->run('DELETE FROM counters WHERE expires<=?',[$now]);
   $this->run('INSERT INTO counters VALUES(?,?,?,?,?) ON CONFLICT(scope,subject,bucket) DO UPDATE SET hits=hits+1',[$scope,$subject,$bucket,1,$end]);
   $n=(int)$this->run('SELECT hits FROM counters WHERE scope=? AND subject=? AND bucket=?',[$scope,$subject,$bucket])->fetchColumn();$this->db->exec('COMMIT');
   $exceeded=$n>(int)$r['max_hits'];return ['allowed'=>$r['mode']==='observe'||!$exceeded,'would_limit'=>$exceeded,'mode'=>$r['mode'],'hits'=>$n,'retry_after'=>$exceeded?$end-$now:0];
  }catch(\Throwable $e){$this->db->exec('ROLLBACK');throw $e;}
 }
 public function setProduct(string $product,array $countries):void {
  if(!preg_match('/^[A-Za-z0-9_-]{1,64}$/D',$product)||!array_is_list($countries)||count($countries)>250)throw new \InvalidArgumentException('Invalid product/countries');
  foreach($countries as $c)if(!is_string($c)||!preg_match('/^[A-Z]{2}$/D',$c))throw new \InvalidArgumentException('Country codes must be uppercase two-letter codes');
  $countries=array_values(array_unique($countries));sort($countries);
  $this->db->beginTransaction();try{$this->run('INSERT INTO products VALUES(?,?) ON CONFLICT(product) DO UPDATE SET countries=excluded.countries',[$product,json_encode($countries)]);$this->audit('products.update',compact('product','countries'));$this->db->commit();}catch(\Throwable $e){$this->db->rollBack();throw $e;}
 }
 public function eligibility(string $product,string $country):array {
  if(!preg_match('/^[A-Za-z0-9_-]{1,64}$/D',$product)||!preg_match('/^[A-Z]{2}$/D',$country))throw new \InvalidArgumentException('Invalid product/country');
  $row=$this->run('SELECT countries FROM products WHERE product=?',[$product])->fetchColumn();$allowed=$row!==false&&in_array($country,json_decode($row,true,512,JSON_THROW_ON_ERROR),true);
  return ['product'=>$product,'shipping_country'=>$country,'allowed'=>$allowed,'reason'=>$allowed?'available':($row===false?'unconfigured_product':'unsupported_destination')];
 }
}
