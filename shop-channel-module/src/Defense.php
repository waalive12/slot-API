<?php
declare(strict_types=1);
namespace Shop;
/** Server-to-server protection for three fixed sensitive business operations only. */
final class Defense {
 public function __construct(private Core $core) {
  $core->db->exec('CREATE TABLE IF NOT EXISTS operation_denies(id INTEGER PRIMARY KEY, scope TEXT NOT NULL, cidr TEXT NOT NULL, expires INTEGER NOT NULL, note TEXT NOT NULL, UNIQUE(scope,cidr)); CREATE INDEX IF NOT EXISTS denies_scope_expiry ON operation_denies(scope,expires);');
 }
 private static function scope(string $s):void {if(!in_array($s,['login','register','coupon'],true))throw new \InvalidArgumentException('Only login, register, coupon are protected');}
 private static function address(string $ip):string {
  if(!filter_var($ip,FILTER_VALIDATE_IP))throw new \InvalidArgumentException('Invalid observed client_ip');
  $b=inet_pton($ip);
  if(strlen($b)===16 && substr($b,0,12)===str_repeat("\0",10)."\xff\xff") return inet_ntop(substr($b,12));
  return inet_ntop($b);
 }
 private static function validate(array $r):array {
  foreach(['scope','cidr'] as $k)if(!isset($r[$k])||!is_string($r[$k]))throw new \InvalidArgumentException('scope and cidr strings required');
  self::scope($r['scope']); [$cidr,$net,$prefix]=Core::network($r['cidr']);
  if($prefix===0)throw new \InvalidArgumentException('All-address /0 deny is forbidden');
  // Normalize IPv4-mapped IPv6 to v4, avoiding equivalent-address bypass.
  if(strlen($net)===16&&substr($net,0,12)===str_repeat("\0",10)."\xff\xff") {
   if($prefix<96)throw new \InvalidArgumentException('Use native IPv4 CIDR');
   $cidr=Core::network(inet_ntop(substr($net,12)).'/'.($prefix-96))[0];
   if($prefix===96)throw new \InvalidArgumentException('All-address /0 deny is forbidden');
  }
  $expires=$r['expires_at']??null;$note=$r['note']??'';
  if(!is_int($expires)||$expires<=time()||$expires>time()+366*86400)throw new \InvalidArgumentException('Expiry must be within next 366 days');
  if(!is_string($note)||strlen($note)>250)throw new \InvalidArgumentException('Invalid note');
  return [$r['scope'],$cidr,$expires,$note];
 }
 private function audit(string $action,array $detail):void {$this->core->run('INSERT INTO audit(ts,action,detail) VALUES(?,?,?)',[time(),$action,json_encode($detail,JSON_THROW_ON_ERROR)]);}
 private function transaction(callable $fn):mixed {
  $this->core->db->beginTransaction();try{$r=$fn();$this->core->db->commit();return $r;}catch(\Throwable $e){$this->core->db->rollBack();throw $e;}
 }
 public function list():array {return $this->core->run('SELECT * FROM operation_denies ORDER BY id')->fetchAll(\PDO::FETCH_ASSOC);}
 public function import(array $rows):int {
  if(!array_is_list($rows)||count($rows)<1||count($rows)>500)throw new \InvalidArgumentException('Supply 1–500 entries');
  $valid=[];foreach($rows as $r){if(!is_array($r))throw new \InvalidArgumentException('Invalid entry');$valid[]=self::validate($r);}
  return $this->transaction(function()use($valid){foreach($valid as $v)$this->core->run('INSERT INTO operation_denies(scope,cidr,expires,note) VALUES(?,?,?,?) ON CONFLICT(scope,cidr) DO UPDATE SET expires=excluded.expires,note=excluded.note',$v);$this->audit('operation_denies.import',['entries'=>array_map(fn($v)=>['scope'=>$v[0],'cidr'=>$v[1],'expires_at'=>$v[2]],$valid)]);return count($valid);});
 }
 public function update(int $id,array $row):bool {
  $valid=self::validate($row);
  return $this->transaction(function()use($id,$valid){if(!$this->core->run('SELECT 1 FROM operation_denies WHERE id=?',[$id])->fetchColumn())return false;
   $other=$this->core->run('SELECT id FROM operation_denies WHERE scope=? AND cidr=? AND id<>?',[$valid[0],$valid[1],$id])->fetchColumn();if($other!==false)throw new \InvalidArgumentException('Duplicate scope and network');
   $this->core->run('UPDATE operation_denies SET scope=?,cidr=?,expires=?,note=? WHERE id=?',[...$valid,$id]);$this->audit('operation_denies.update',['id'=>$id,'scope'=>$valid[0],'cidr'=>$valid[1],'expires_at'=>$valid[2]]);return true;});
 }
 public function delete(int $id):bool {return $this->transaction(function()use($id){$changed=$this->core->run('DELETE FROM operation_denies WHERE id=?',[$id])->rowCount()>0;if($changed)$this->audit('operation_denies.delete',['id'=>$id]);return $changed;});}
 public function guard(string $scope,string $subject,string $observedIp,int $now):array {
  self::scope($scope);if(!preg_match('/^[a-f0-9]{64}$/D',$subject))throw new \InvalidArgumentException('Invalid pseudonymous subject');$ip=self::address($observedIp);
  foreach($this->core->run('SELECT cidr FROM operation_denies WHERE scope=? AND expires>?',[$scope,$now])->fetchAll(\PDO::FETCH_COLUMN) as $cidr) {
   if(Core::contains($cidr,$ip))return ['allowed'=>false,'status'=>403,'reason'=>'operation_network_denied','retry_after'=>0];
  }
  $r=$this->core->consume($scope,$subject,$now);return [...$r,'status'=>$r['allowed']?200:429,'reason'=>$r['allowed']?'allowed':'rate_limited'];
 }
}
