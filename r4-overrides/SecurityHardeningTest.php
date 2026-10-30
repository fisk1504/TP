<?php
namespace Tests\Feature;

use App\Models\SecurityBlock;
use App\Models\User;
use Illuminate\Foundation\Testing\RefreshDatabase;
use Illuminate\Support\Str;
use Tests\TestCase;

class SecurityHardeningTest extends TestCase
{
    use RefreshDatabase;

    protected function setUp(): void
    {
        parent::setUp();
        config([
            'bee.domains.panel'=>'acesso.busqueencontreempresas.com.br',
            'bee.domains.api'=>'api.busqueencontreempresas.com.br',
            'bee.domains.analytics'=>'analytics.busqueencontreempresas.com.br',
            'bee.firewall_enabled'=>true,
            'bee.trusted_proxies'=>[],
            'bee.require_admin_mfa'=>true,
            'session.domain'=>null,
            'session.secure'=>true,
            'session.http_only'=>true,
            'session.same_site'=>'strict',
        ]);
    }

    public function test_https_response_has_security_headers(): void
    {
        $r=$this->withServerVariables(['HTTPS'=>'on','REMOTE_ADDR'=>'198.51.100.10'])
            ->withHeader('Host','acesso.busqueencontreempresas.com.br')
            ->get('https://acesso.busqueencontreempresas.com.br/up');
        $r->assertOk();
        $r->assertHeader('X-Content-Type-Options','nosniff');
        $r->assertHeader('Referrer-Policy','strict-origin-when-cross-origin');
        $r->assertHeader('X-Frame-Options','DENY');
        $this->assertStringContainsString("frame-ancestors 'none'",(string)$r->headers->get('Content-Security-Policy'));
        $this->assertStringContainsString('camera=()', (string)$r->headers->get('Permissions-Policy'));
        $this->assertStringContainsString('max-age=',(string)$r->headers->get('Strict-Transport-Security'));
    }

    public function test_firewall_persists_strikes_and_blocks_fifth_probe(): void
    {
        $ip='198.51.100.21';
        for($i=0;$i<4;$i++){
            $this->withServerVariables(['REMOTE_ADDR'=>$ip])->withHeader('Host','acesso.busqueencontreempresas.com.br')->get('/wp-admin')->assertNotFound();
        }
        $row=SecurityBlock::query()->where('ip',$ip)->where('reason','suspicious_path')->firstOrFail();
        $this->assertSame(4,(int)$row->hits);
        $this->withServerVariables(['REMOTE_ADDR'=>$ip])->withHeader('Host','acesso.busqueencontreempresas.com.br')->get('/up')->assertStatus(429);
    }

    public function test_untrusted_forwarded_for_is_ignored(): void
    {
        $remote='198.51.100.31';$spoof='203.0.113.77';
        $this->withServerVariables(['REMOTE_ADDR'=>$remote])->withHeaders(['Host'=>'acesso.busqueencontreempresas.com.br','X-Forwarded-For'=>$spoof])->get('/.env')->assertNotFound();
        $this->assertDatabaseHas('security_blocks',['ip'=>$remote,'reason'=>'suspicious_path']);
        $this->assertDatabaseMissing('security_blocks',['ip'=>$spoof]);
    }

    public function test_session_idle_timeout_logs_user_out(): void
    {
        $u=User::create(['name'=>'Session QA','email'=>'session-qa@example.test','password'=>Str::random(40),'status'=>'ACTIVE']);
        $this->actingAs($u)->withSession(['bee_session_started_at'=>time()-4000,'bee_session_last_activity'=>time()-1900])
            ->withServerVariables(['REMOTE_ADDR'=>'198.51.100.41'])
            ->withHeader('Host','acesso.busqueencontreempresas.com.br')
            ->get('https://acesso.busqueencontreempresas.com.br/')
            ->assertRedirect(route('login'));
        $this->assertGuest();
    }

    public function test_critical_mutation_requires_recent_password(): void
    {
        $u=User::create(['name'=>'Reauth QA','email'=>'reauth-qa@example.test','password'=>Str::random(40),'status'=>'ACTIVE']);
        $this->actingAs($u)->withSession(['bee_session_started_at'=>time(),'bee_session_last_activity'=>time()])
            ->withServerVariables(['REMOTE_ADDR'=>'198.51.100.51'])
            ->withHeader('Host','acesso.busqueencontreempresas.com.br')
            ->post('https://acesso.busqueencontreempresas.com.br/sites',[])
            ->assertRedirect(route('reauth.form'));
    }

    public function test_session_cookie_configuration_is_host_only_and_strict(): void
    {
        $this->assertNull(config('session.domain'));
        $this->assertTrue((bool)config('session.secure'));
        $this->assertTrue((bool)config('session.http_only'));
        $this->assertSame('strict',config('session.same_site'));
    }
}
