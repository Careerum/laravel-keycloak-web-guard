<?php

declare(strict_types=1);

namespace Careerum\KeycloakWebGuard\Tests\Auth;

use Careerum\KeycloakWebGuard\Exceptions\InvalidCallbackStateException;
use Careerum\KeycloakWebGuard\Exceptions\KeycloakCallbackException;
use Careerum\KeycloakWebGuard\Tests\TestCase;
use Illuminate\Support\Facades\Route;

class InvalidCallbackStateTest extends TestCase
{
    protected function defineEnvironment($app): void
    {
        parent::defineEnvironment($app);

        $app['config']->set('app.key', 'base64:AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=');
    }

    protected function setUp(): void
    {
        parent::setUp();

        config(['keycloak-web.redirect_url' => '/']);
        Route::middleware('web')->get('/', fn () => response('destination'));
    }

    public function testFirstInvalidCallbackRedirectsOnlyOnceWithoutAnIntendedUrl(): void
    {
        $this->get('/callback')->assertRedirectContains('/?retry_login=');

        $this->withoutExceptionHandling();
        $this->expectException(InvalidCallbackStateException::class);
        $this->get('/callback');
    }

    public function testChangedIntendedUrlCannotResetRetryBudget(): void
    {
        $this->withSession(['url.intended' => '/first']);
        $this->get('/callback')->assertRedirectContains('/first?retry_login=');

        $this->withSession(['url.intended' => '/second']);
        $this->withoutExceptionHandling();
        $this->expectException(InvalidCallbackStateException::class);
        $this->get('/callback');
    }

    public function testSuccessfulStateClearsRetryMarker(): void
    {
        $this->get('/callback')->assertRedirectContains('/?retry_login=');

        $this->withSession(['_keycloak_state' => 'expected']);
        $this->get('/callback?state=expected')->assertRedirect(route('keycloak.login'));

        $this->get('/callback')->assertRedirectContains('/?retry_login=');
    }

    public function testExpiredRetryWindowAllowsAnotherAttempt(): void
    {
        $this->withSession(['_keycloak_retry_login' => time() - 31]);

        $this->get('/callback')->assertRedirectContains('/?retry_login=');
    }

    public function testIdentityProviderErrorKeepsTheGeneralException(): void
    {
        $this->withoutExceptionHandling();
        $this->expectException(KeycloakCallbackException::class);
        $this->expectExceptionMessage('[Keycloak Error] provider rejected request');

        $this->get('/callback?error=provider%20rejected%20request');
    }
}
