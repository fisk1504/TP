<?php
namespace BeeUpdater;
final class BackupManager {
    public function __construct(private readonly string $base) {}
    public function create(string $releaseId,array $files): array {
        $dir=$this->base.'/storage/app/private/backups/'.gmdate('Ymd-His').'-'.preg_replace('/[^A-Za-z0-9._-]/','_', $releaseId);
        if(!is_dir($dir)&&!mkdir($dir,0700,true))throw new \RuntimeException('Cannot create backup directory');
        $db=$dir.'/database.sql';
        $this->backupDatabase($db);
        $zipPath=$dir.'/files.zip'; $zip=new \ZipArchive(); if($zip->open($zipPath,\ZipArchive::CREATE|\ZipArchive::OVERWRITE)!==true)throw new \RuntimeException('Cannot create file backup');
        $seen=[];
        foreach($files as $relative){$relative=str_replace('\\','/',$relative);if(isset($seen[$relative]))continue;$seen[$relative]=1;$full=$this->base.'/'.$relative;if(is_file($full))$zip->addFile($full,$relative);}
        foreach(['release.json','storage/app/private/installed-release.json','.env'] as $relative){$full=$this->base.'/'.$relative;if(is_file($full)&&!isset($seen[$relative]))$zip->addFile($full,$relative);}
        $zip->close();
        if(!is_file($zipPath)||filesize($zipPath)===0)throw new \RuntimeException('File backup validation failed');
        $meta=['release_id'=>$releaseId,'database'=>basename($db),'database_sha256'=>hash_file('sha256',$db),'files'=>basename($zipPath),'files_sha256'=>hash_file('sha256',$zipPath),'created_at'=>gmdate('c')];
        file_put_contents($dir.'/backup.json',json_encode($meta,JSON_PRETTY_PRINT|JSON_UNESCAPED_SLASHES),LOCK_EX);return ['directory'=>$dir,'meta'=>$meta];
    }
    public function restore(array $backup): void {
        $dir=(string)$backup['directory'];$meta=(array)$backup['meta'];$db=$dir.'/'.$meta['database'];$files=$dir.'/'.$meta['files'];
        if(!hash_equals((string)$meta['database_sha256'],hash_file('sha256',$db)))throw new \RuntimeException('Database backup hash mismatch');
        if(!hash_equals((string)$meta['files_sha256'],hash_file('sha256',$files)))throw new \RuntimeException('File backup hash mismatch');
        $this->restoreDatabase($db);$zip=new \ZipArchive();if($zip->open($files)!==true)throw new \RuntimeException('Cannot open file backup');$zip->extractTo($this->base);$zip->close();
    }
    private function backupDatabase(string $target): void {
        $pdo=Common::pdo();$out="-- BEE PDO SQL BACKUP\nSET FOREIGN_KEY_CHECKS=0;\n";$tables=$pdo->query('SHOW TABLES')->fetchAll(\PDO::FETCH_COLUMN);
        foreach($tables as $table){$q=$pdo->query('SHOW CREATE TABLE `'.str_replace('`','``',(string)$table).'`')->fetch();$create=array_values($q)[1]??null;if(!$create)continue;$out.="DROP TABLE IF EXISTS `{$table}`;\n{$create};\n";$st=$pdo->query('SELECT * FROM `'.str_replace('`','``',(string)$table).'`');while($row=$st->fetch(\PDO::FETCH_ASSOC)){$vals=array_map(static fn($v)=>$v===null?'NULL':$pdo->quote((string)$v),array_values($row));$cols=array_map(static fn($c)=>'`'.str_replace('`','``',(string)$c).'`',array_keys($row));$out.='INSERT INTO `'.$table.'` ('.implode(',',$cols).') VALUES ('.implode(',',$vals).");\n";}}
        $out.="SET FOREIGN_KEY_CHECKS=1;\n";if(file_put_contents($target,$out,LOCK_EX)===false||filesize($target)===0)throw new \RuntimeException('Database backup failed');
    }
    private function restoreDatabase(string $file): void {
        $pdo=Common::pdo();$sql=(string)file_get_contents($file);$statement='';$quote=null;$length=strlen($sql);for($i=0;$i<$length;$i++){$ch=$sql[$i];if($quote!==null){$statement.=$ch;if($ch===$quote&&($i===0||$sql[$i-1]!=="\\"))$quote=null;continue;}if($ch==="'"||$ch==='"'){$quote=$ch;$statement.=$ch;continue;}if($ch===';'){$trim=trim($statement);$statement='';if($trim!==''&&!str_starts_with($trim,'--'))$pdo->exec($trim);continue;}$statement.=$ch;}if(trim($statement)!=='')$pdo->exec(trim($statement));
    }
}
