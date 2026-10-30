<?php
namespace BeeUpdater;
final class Common {
    public static function base(): string { return dirname(__DIR__,2); }
    public static function env(): array { $p=self::base().'/.env'; $o=[]; if(!is_file($p))return $o; foreach(file($p,FILE_IGNORE_NEW_LINES|FILE_SKIP_EMPTY_LINES)?:[] as $l){if(str_starts_with(trim($l),'#')||!str_contains($l,'='))continue;[$k,$v]=explode('=',$l,2);$o[trim($k)]=trim(trim($v),"\"'");}return $o; }
    public static function pdo(): \PDO { $e=self::env(); return new \PDO('mysql:host='.$e['DB_HOST'].';port='.($e['DB_PORT']??3306).';dbname='.$e['DB_DATABASE'].';charset=utf8mb4',$e['DB_USERNAME'],$e['DB_PASSWORD'],[\PDO::ATTR_ERRMODE=>\PDO::ERRMODE_EXCEPTION,\PDO::ATTR_DEFAULT_FETCH_MODE=>\PDO::FETCH_ASSOC]); }
    public static function installed(): array { $p=self::base().'/storage/app/private/installed-release.json'; return is_file($p)?(json_decode((string)file_get_contents($p),true)?:[]):[]; }
    public static function code(): array { return json_decode((string)file_get_contents(self::base().'/release.json'),true)?:[]; }
    public static function csrf(): string { if(session_status()!==PHP_SESSION_ACTIVE)session_start(); return $_SESSION['bee_update_csrf']??=bin2hex(random_bytes(24)); }
    public static function checkCsrf(string $v): void { if(session_status()!==PHP_SESSION_ACTIVE)session_start(); if(!hash_equals((string)($_SESSION['bee_update_csrf']??''),$v))throw new \RuntimeException('CSRF failed'); }
}
