<?php
namespace BeeUpdater;

final class RestoreManager
{
    public function restore(string $databaseSql, string $filesZip, ?string $expectedDatabaseSha256 = null, ?string $expectedFilesSha256 = null): array
    {
        $this->assertFile($databaseSql, 'database backup');
        $this->assertFile($filesZip, 'file backup');
        $dbHash = hash_file('sha256', $databaseSql);
        $filesHash = hash_file('sha256', $filesZip);
        if ($expectedDatabaseSha256 !== null && !hash_equals(strtolower($expectedDatabaseSha256), strtolower($dbHash))) throw new \RuntimeException('Database backup hash mismatch.');
        if ($expectedFilesSha256 !== null && !hash_equals(strtolower($expectedFilesSha256), strtolower($filesHash))) throw new \RuntimeException('File backup hash mismatch.');
        $zip = new \ZipArchive();
        if ($zip->open($filesZip) !== true) throw new \RuntimeException('Cannot open file backup.');
        try { for ($i=0;$i<$zip->numFiles;$i++) $this->assertSafeRelativePath((string)$zip->getNameIndex($i)); } finally { $zip->close(); }
        $this->restoreDatabase($databaseSql);
        $this->restoreFiles($filesZip);
        return ['database_sha256'=>$dbHash,'files_sha256'=>$filesHash,'restored_at'=>gmdate('c')];
    }
    public function restoreDatabase(string $databaseSql): void
    {
        $this->assertFile($databaseSql,'database backup');
        $pdo=Common::pdo();
        foreach($this->splitSql((string)file_get_contents($databaseSql)) as $statement){$trim=trim($statement);if($trim!=='')$pdo->exec($trim);}
    }
    public function restoreFiles(string $filesZip): void
    {
        $this->assertFile($filesZip,'file backup');$zip=new \ZipArchive();if($zip->open($filesZip)!==true)throw new \RuntimeException('Cannot open file backup.');
        try { for($i=0;$i<$zip->numFiles;$i++)$this->assertSafeRelativePath((string)$zip->getNameIndex($i));if(!$zip->extractTo(Common::base()))throw new \RuntimeException('File restore failed.'); } finally {$zip->close();}
    }
    private function splitSql(string $sql): array
    {
        $out=[];$statement='';$quote=null;$escaped=false;$lineComment=false;$length=strlen($sql);
        for($i=0;$i<$length;$i++){$ch=$sql[$i];$next=$i+1<$length?$sql[$i+1]:'';
            if($lineComment){if($ch==="\n")$lineComment=false;continue;}
            if($quote===null&&$ch==='-'&&$next==='-'){$lineComment=true;$i++;continue;}
            if($quote!==null){$statement.=$ch;if($escaped){$escaped=false;continue;}if($ch==='\\'){$escaped=true;continue;}if($ch===$quote){if($next===$quote){$statement.=$next;$i++;}else{$quote=null;}}continue;}
            if($ch==="'"||$ch==='"'||$ch==='`'){$quote=$ch;$statement.=$ch;continue;}
            if($ch===';'){if(trim($statement)!=='')$out[]=$statement;$statement='';continue;}$statement.=$ch;
        }
        if(trim($statement)!=='')$out[]=$statement;return $out;
    }
    private function assertSafeRelativePath(string $path): void
    {
        $normalized=str_replace('\\','/',$path);if($normalized===''||str_contains($normalized,"\0")||str_starts_with($normalized,'/')||preg_match('/^[A-Za-z]:\//',$normalized))throw new \RuntimeException('Unsafe backup path: '.$path);if(in_array('..',explode('/',$normalized),true))throw new \RuntimeException('Unsafe backup path: '.$path);
    }
    private function assertFile(string $path,string $label): void {if(!is_file($path)||filesize($path)<=0)throw new \RuntimeException('Missing or empty '.$label.'.');}
}
