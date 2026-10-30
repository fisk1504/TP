<?php
use App\Http\Middleware\ApiTokenAuth;
use App\Http\Middleware\EnsureSiteAccess;
use App\Http\Middleware\SecurityHeaders;
use App\Http\Middleware\BeeApplicationFirewall;
use App\Http\Middleware\EnsureMfa;
use App\Http\Middleware\RequireRecentPassword;
use App\Http\Middleware\SessionSecurity;
use Illuminate\Foundation\Application;
use Illuminate\Foundation\Configuration\Exceptions;
use Illuminate\Foundation\Configuration\Middleware;
use Illuminate\Support\Facades\Route;

return Application::configure(basePath: dirname(__DIR__))
    ->withRouting(
        commands: __DIR__.'/../routes/console.php',
        health: '/up',
        using: function (): void {
            Route::middleware(['web', SecurityHeaders::class])
                ->domain(config('bee.domains.panel'))
                ->group(base_path('routes/web.php'));

            Route::middleware(['api', SecurityHeaders::class])
                ->domain(config('bee.domains.api'))
                ->prefix('api/v1')
                ->group(base_path('routes/api.php'));

            Route::middleware(['api', SecurityHeaders::class])
                ->domain(config('bee.domains.analytics'))
                ->prefix('v1')
                ->group(base_path('routes/analytics.php'));
        },
    )
    ->withMiddleware(function (Middleware $middleware): void {
        $middleware->prepend(BeeApplicationFirewall::class);
        $middleware->alias([
            'api.token' => ApiTokenAuth::class,
            'site.access' => EnsureSiteAccess::class,
            'mfa' => EnsureMfa::class,
            'reauth' => RequireRecentPassword::class,
            'session.guard' => SessionSecurity::class,
        ]);
    })
    ->withExceptions(function (Exceptions $exceptions): void {
        //
    })->create();
