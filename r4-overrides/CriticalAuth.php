<?php
namespace BeeUpdater;
final class CriticalAuth {
 public function authenticate(string $email,string $password,string $mfaCode=''):array{
  $pdo=Common::pdo();$pdo->beginTransaction();
  try{$has=(bool)$pdo->query("SHOW COLUMNS FROM users LIKE 'mfa_last_timestep'")->fetch();$expr=$has?'u.mfa_last_timestep':'NULL AS mfa_last_timestep';$s=$pdo->prepare("SELECT u.id,u.password,u.mfa_secret,u.mfa_recovery_codes,u.mfa_confirmed_at,{$expr},r.name role FROM users u LEFT JOIN roles r ON r.id=u.platform_role_id WHERE u.email=? AND u.status='ACTIVE' LIMIT 1 FOR UPDATE");$s->execute([$email]);$u=$s->fetch();if(!$u||!in_array($u['role'],['PLATFORM_OWNER','PLATFORM_ADMIN'],true)||!password_verify($password,(string)$u['password'])){$pdo->rollBack();return['ok'=>false,'reason'=>'invalid'];}
   if(Common::envBool('BEE_REQUIRE_ADMIN_MFA',true)){if(empty($u['mfa_confirmed_at'])||empty($u['mfa_secret'])){$pdo->rollBack();return['ok'=>false,'reason'=>'mfa_enrollment_required'];}$accepted=false;$counter=(new TotpVerifier())->matchedCounter((string)$u['mfa_secret'],$mfaCode);$last=$has?($u['mfa_last_timestep']===null?null:(int)$u['mfa_last_timestep']):$this->overlayLastCounter((string)$u['id']);if($counter!==null&&($last===null||$counter>$last)){if($has){$q=$pdo->prepare('UPDATE users SET mfa_last_timestep=?,updated_at=NOW() WHERE id=? AND (mfa_last_timestep IS NULL OR mfa_last_timestep<?)');$q->execute([$counter,$u['id'],$counter]);$accepted=$q->rowCount()===1;}else{$this->writeOverlayCounter((string)$u['id'],$counter);$accepted=true;}}
    if(!$accepted){$h=hash('sha256',strtoupper(trim($mfaCode)));$codes=json_decode((string)($u['mfa_recovery_codes']??'[]'),true);if(!is_array($codes))$codes=[];$idx=array_search($h,$codes,true);if($idx!==false){unset($codes[$idx]);$q=$pdo->prepare('UPDATE users SET mfa_recovery_codes=?,updated_at=NOW() WHERE id=?');$q->execute([json_encode(array_values($codes),JSON_UNESCAPED_SLASHES),$u['id']]);$accepted=true;}}
    if(!$accepted){$pdo->rollBack();return['ok'=>false,'reason'=>'mfa_invalid'];}}
   $pdo->commit();return['ok'=>true,'user'=>['id'=>$u['id'],'role'=>$u['role']]];
  }catch(\Throwable$e){if($pdo->inTransaction())$pdo->rollBack();throw$e;}
 }
 private function overlayStatePath():string{return Common::base().'/storage/app/private/overlay-mfa-state.json';}
 private function overlayLastCounter(string$id):?int{$p=$this->overlayStatePath();$d=is_file($p)?(json_decode((string)file_get_contents($p),true)?:[]):[];$v=$d['users'][$id]??null;return$v===null?null:(int)$v;}
 private function writeOverlayCounter(string$id,int$c):void{$p=$this->overlayStatePath();$dir=dirname($p);if(!is_dir($dir))mkdir($dir,0700,true);$fh=fopen($p,'c+');if(!$fh)throw new \RuntimeException('Cannot persist overlay MFA state.');try{if(!flock($fh,LOCK_EX))throw new \RuntimeException('Cannot lock overlay MFA state.');rewind($fh);$raw=stream_get_contents($fh);$d=$raw!==false&&trim($raw)!==''?(json_decode($raw,true)?:[]):[];$d['users'][$id]=$c;$d['updated_at']=gmdate('c');ftruncate($fh,0);rewind($fh);fwrite($fh,json_encode($d,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES));fflush($fh);flock($fh,LOCK_UN);}finally{fclose($fh);}@chmod($p,0600);}
}
