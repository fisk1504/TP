<?php
namespace Tests\Feature;
use Tests\TestCase;
use Illuminate\Foundation\Testing\RefreshDatabase;
class ApiAuthTest extends TestCase
{
    use RefreshDatabase;

    public function test_api_sites_requires_token(): void
    {
        config(['bee.domains.api'=>'api.busqueencontreempresas.com.br']);
        $response=$this->withHeader('Host','api.busqueencontreempresas.com.br')
            ->getJson('https://api.busqueencontreempresas.com.br/api/v1/sites');
        $response->assertStatus(401);
    }
}
