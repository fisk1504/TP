<?php
namespace Tests\Feature;
use Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
class AnalyticsDisabledTest extends TestCase
{
    use RefreshDatabase;

    public function test_ingest_is_disabled_by_default(): void
    {
        config(['bee.analytics_ingest_enabled'=>false,'bee.domains.analytics'=>'analytics.busqueencontreempresas.com.br']);
        $response=$this->withHeader('Host','analytics.busqueencontreempresas.com.br')
            ->postJson('https://analytics.busqueencontreempresas.com.br/v1/events',['event_name'=>'page_view']);
        $response->assertStatus(503);
    }
}
