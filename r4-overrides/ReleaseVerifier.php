<?php
namespace BeeUpdater;
final class ReleaseVerifier {
    public function __construct(private readonly string $base, private readonly TrustStore $trustStore) {}
    public function verifyPackage(string $zipPath, string $currentVersion): array
    {
        if (!is_file($zipPath)) throw new \RuntimeException('Update package not found.');
        $zip = new \ZipArchive();
        if ($zip->open($zipPath) !== true) throw new \RuntimeException('Update package is not a valid ZIP.');
        try {
            $names = [];
            for ($i = 0; $i < $zip->numFiles; $i++) {
                $name = (string) $zip->getNameIndex($i);
                $this->assertSafeArchivePath($name);
                if (isset($names[$name])) throw new \RuntimeException('Duplicate archive entry: '.$name);
                $names[$name] = true;
            }
            foreach (['release.json','manifest.json','signature-payload.json','signature.ed25519'] as $needed) {
                if (!isset($names[$needed])) throw new \RuntimeException('Required update file missing: '.$needed);
            }
            $releaseRaw = (string) $zip->getFromName('release.json');
            $manifestRaw = (string) $zip->getFromName('manifest.json');
            $signaturePayloadRaw = (string) $zip->getFromName('signature-payload.json');
            $signatureRaw = (string) $zip->getFromName('signature.ed25519');
            $release = json_decode($releaseRaw, true, flags: JSON_THROW_ON_ERROR);
            $manifest = json_decode($manifestRaw, true, flags: JSON_THROW_ON_ERROR);
            $signaturePayload = json_decode($signaturePayloadRaw, true, flags: JSON_THROW_ON_ERROR);
            $this->assertReleaseShape($release);
            $this->assertCompatibility($release, $currentVersion);
            $this->assertManifestBinding($release, $manifestRaw, $signaturePayload);
            $key = $this->trustStore->resolveReleaseKey((string) $release['signature_key_id'], new \DateTimeImmutable((string) ($release['built_at'] ?? 'now')));
            if (!hash_equals((string) $key['key_id'], (string) ($signaturePayload['key_id'] ?? ''))) throw new \RuntimeException('Signature payload key mismatch.');
            if (!hash_equals((string) $release['release_id'], (string) ($signaturePayload['release_id'] ?? ''))) throw new \RuntimeException('Signature payload release mismatch.');
            $this->verifySignature($signaturePayload, $signatureRaw, (string) $key['public_key_base64']);
            $this->verifyFiles($zip, $manifest);
            return ['release'=>$release,'manifest'=>$manifest,'signature_payload'=>$signaturePayload,'trust_store_version'=>(int)($key['trust_store_version'] ?? 0)];
        } finally { $zip->close(); }
    }
    private function assertSafeArchivePath(string $path): void { if ($path===''||str_contains($path,"\0")||str_contains(str_replace('\\','/',$path),'../')||str_starts_with($path,'/')||preg_match('/^[A-Za-z]:[\\\\\/]/',$path)) throw new \RuntimeException('Unsafe update archive path: '.$path); }
    private function assertReleaseShape(array $release): void {
        if (($release['signature_algorithm'] ?? '') !== 'Ed25519') throw new \RuntimeException('Unsupported update signature algorithm.');
        foreach (['version','schema_version','release_id','manifest_sha256','signature_key_id'] as $field) if (!isset($release[$field]) || $release[$field]==='') throw new \RuntimeException('Missing release field: '.$field);
    }
    private function assertCompatibility(array $release, string $currentVersion): void
    {
        $targetVersion = (string) ($release['version'] ?? '0.0.0');
        if (version_compare($targetVersion, $currentVersion, '<=')) {
            throw new \RuntimeException('Update downgrade/replay rejected: target version must be newer than installed version.');
        }

        $range = (array) ($release['compatible_installed_versions'] ?? []);
        if (count($range) !== 2 || version_compare($currentVersion,(string)$range[0],'<') || version_compare($currentVersion,(string)$range[1],'>')) throw new \RuntimeException('Installed version is outside the update compatibility range.');
        $migrations=(array)($release['migration_range']??[]); if((int)($migrations['to_schema']??-1)!==(int)$release['schema_version'])throw new \RuntimeException('Release schema and migration range disagree.');
    }
    private function assertManifestBinding(array $release,string $manifestRaw,array $signaturePayload): void {
        $manifestHash=hash('sha256',$manifestRaw); if(!hash_equals(strtolower((string)$release['manifest_sha256']),$manifestHash))throw new \RuntimeException('Manifest SHA-256 does not match release metadata.');
        if(!hash_equals($manifestHash,strtolower((string)($signaturePayload['manifest_sha256']??''))))throw new \RuntimeException('Signature payload does not bind this manifest.');
        $releaseForHash=$release;unset($releaseForHash['release_sha256']);$releaseHash=hash('sha256',$this->canonicalJson($releaseForHash));
        if(!hash_equals($releaseHash,strtolower((string)($signaturePayload['release_sha256']??''))))throw new \RuntimeException('Signature payload does not bind release metadata.');
    }
    private function verifySignature(array $payload,string $signatureRaw,string $publicKeyBase64): void {
        $sig=$this->decodeBinary($signatureRaw,SODIUM_CRYPTO_SIGN_BYTES,'signature');$public=$this->decodeBinary($publicKeyBase64,SODIUM_CRYPTO_SIGN_PUBLICKEYBYTES,'release public key');
        if(!sodium_crypto_sign_verify_detached($sig,$this->canonicalJson($payload),$public))throw new \RuntimeException('Update signature verification failed.');
    }
    private function verifyFiles(\ZipArchive $zip,array $manifest): void {
        $files=(array)($manifest['files']??[]);if($files===[])throw new \RuntimeException('Update manifest has no files.');
        foreach($files as $file){$path=(string)($file['path']??'');$expected=strtolower((string)($file['sha256']??''));$size=(int)($file['size']??-1);$this->assertSafeArchivePath($path);if(!preg_match('/^[a-f0-9]{64}$/',$expected))throw new \RuntimeException('Bad file digest: '.$path);$content=$zip->getFromName($path);if($content===false)throw new \RuntimeException('Manifest file missing from archive: '.$path);if(strlen($content)!==$size||!hash_equals($expected,hash('sha256',$content)))throw new \RuntimeException('Update file integrity failure: '.$path);}
    }
    private function decodeBinary(string $value,int $length,string $label): string {$trimmed=trim($value);$decoded=base64_decode($trimmed,true);$binary=$decoded!==false?$decoded:$value;if(strlen($binary)!==$length)throw new \RuntimeException('Invalid '.$label.' length.');return $binary;}
    private function canonicalJson(array $data): string { $sorted=$this->sortRecursive($data);return json_encode($sorted,JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE|JSON_THROW_ON_ERROR); }
    private function sortRecursive(mixed $value): mixed { if(!is_array($value))return $value;if(array_is_list($value))return array_map(fn($v)=>$this->sortRecursive($v),$value);ksort($value,SORT_STRING);foreach($value as $k=>$v)$value[$k]=$this->sortRecursive($v);return $value; }
}
