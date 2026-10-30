<?php
namespace App\Services;

use App\Models\AuditLog;

final class AuditChainVerifier
{
    public function verify(): array
    {
        $expectedPrevious=str_repeat('0',64);$checked=0;
        foreach(AuditLog::query()->orderBy('id')->cursor() as $row){
            $id=(int)$row->id;$previous=(string)($row->previous_hash??'');$record=(string)($row->record_hash??'');
            if(!preg_match('/^[a-f0-9]{64}$/i',$previous)||!preg_match('/^[a-f0-9]{64}$/i',$record))return $this->failure($checked,$id,'missing_or_invalid_hash');
            if(!hash_equals(strtolower($expectedPrevious),strtolower($previous)))return $this->failure($checked,$id,'previous_hash_mismatch');
            $created=$row->created_at;if(!$created)return $this->failure($checked,$id,'missing_created_at');
            $canonical=json_encode([$row->user_id,$row->site_id,$row->action,$row->auditable_type,$row->auditable_id,$row->ip,$row->user_agent,$row->before_json,$row->after_json,$created->toIso8601String(),$previous],JSON_UNESCAPED_SLASHES|JSON_UNESCAPED_UNICODE);
            $calculated=hash('sha256',$canonical?:'');if(!hash_equals(strtolower($record),strtolower($calculated)))return $this->failure($checked,$id,'record_hash_mismatch');
            $expectedPrevious=$record;$checked++;
        }
        return ['ok'=>true,'checked'=>$checked,'head_hash'=>$expectedPrevious,'failed_id'=>null,'reason'=>null];
    }
    private function failure(int $checked,int $id,string $reason): array{return ['ok'=>false,'checked'=>$checked,'head_hash'=>null,'failed_id'=>$id,'reason'=>$reason];}
}
