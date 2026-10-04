<?php

declare(strict_types=1);

namespace Careerum\KeycloakWebGuard\Tests\Auth;

use Careerum\KeycloakWebGuard\Auth\Guard\KeycloakWebGuard;
use Careerum\KeycloakWebGuard\Facades\KeycloakWeb;
use Careerum\KeycloakWebGuard\Tests\TestCase;
use GuzzleHttp\Psr7\Response;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Http\Request;
use PHPUnit\Framework\Attributes\DataProvider;

class KeycloakWebGuardTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // The guard resolves the session off the request.
        $request = Request::create('https://app.example.com/');
        $request->setLaravelSession($this->app['session.store']);
        $this->app->instance('request', $request);
    }

    private function guard(?Authenticatable $user = null): KeycloakWebGuard
    {
        $provider = new class($user) implements UserProvider {
            public function __construct(private ?Authenticatable $user) {}

            public function retrieveById($identifier)
            {
                return $identifier === 'user-uuid' ? $this->user : null;
            }

            public function retrieveByCredentials(array $credentials) { return $this->user; }

            public function validateCredentials(Authenticatable $user, array $credentials) { return true; }

            public function retrieveByToken($identifier, $token) { return null; }

            public function updateRememberToken(Authenticatable $user, $token) {}

            public function rehashPasswordIfRequired(Authenticatable $user, array $credentials, bool $force = false) {}
        };

        return new KeycloakWebGuard('keycloak-web', $provider, $this->app['request']);
    }

    private function queueRefreshResponse(array $overrides = []): array
    {
        $credentials = array_merge([
            'access_token' => $this->jwt(['exp' => time() + 300]),
            'refresh_token' => 'new-refresh-token',
        ], $overrides);
        $this->mockHandler->append(new Response(200, [], json_encode($credentials)));

        return $credentials;
    }

    public function testItRefreshesAnExpiredAccessTokenForAnEstablishedSession(): void
    {
        $user = $this->loggedInUserWithToken($this->expiredCredentials());
        $new = $this->queueRefreshResponse();

        $resolved = $this->guard($user)->user();

        $this->assertSame($user, $resolved);

        $request = $this->mockHandler->getLastRequest();
        $this->assertSame('POST', $request->getMethod());
        parse_str((string) $request->getBody(), $form);
        $this->assertSame('refresh_token', $form['grant_type']);
        $this->assertSame('old-refresh-token', $form['refresh_token']);

        // The renewed credentials replace the expired ones in the session.
        $this->assertSame($new['access_token'], KeycloakWeb::retrieveToken()['access_token']);

        // A separate request uses the renewed token without another refresh.
        $this->assertSame($user, $this->guard($user)->user());
        $this->assertSame(0, $this->mockHandler->count());
    }

    public function testItDoesNotRefreshAValidToken(): void
    {
        $user = $this->loggedInUserWithToken($this->validCredentials());

        $resolved = $this->guard($user)->user();

        $this->assertSame($user, $resolved);
        $this->assertSame(0, $this->mockHandler->count());
    }

    public function testItKeepsATokenlessSession(): void
    {
        $user = $this->loggedInUserWithToken(null);

        $resolved = $this->guard($user)->user();

        $this->assertSame($user, $resolved);
        $this->assertSame(0, $this->mockHandler->count());
    }

    #[DataProvider('refreshFailureProvider')]
    public function testItEndsTheSessionWhenRefreshFails(\Closure $failure): void
    {
        $user = $this->loggedInUserWithToken($this->expiredCredentials());
        $this->mockHandler->append($failure());

        $resolved = $this->guard($user)->user();

        // The local login session is cleared and no code is present for the
        // (empty) Keycloak token, so the user stays unauthenticated.
        $this->assertNull($resolved);
        $this->assertNull(session()->get($this->guardSessionKey()));
        $this->assertNull(KeycloakWeb::retrieveToken());
    }

    public static function refreshFailureProvider(): array
    {
        return [
            'refresh token rejected' => [fn () => new Response(400, [], '{"error":"invalid_grant"}')],
            'transport failure' => [fn () => new \GuzzleHttp\Exception\ConnectException(
                'cURL error 7: Connection refused',
                new \GuzzleHttp\Psr7\Request('POST', 'https://keycloak.example.com/realms/test-realm/protocol/openid-connect/token'),
            )],
        ];
    }

    private function expiredCredentials(): array
    {
        $this->queueOpenIdConfiguration();

        return [
            'access_token' => $this->jwt(['exp' => time() - 60]),
            'refresh_token' => 'old-refresh-token',
        ];
    }

    private function validCredentials(): array
    {
        return [
            'access_token' => $this->jwt(['exp' => time() + 3600]),
            'refresh_token' => 'old-refresh-token',
        ];
    }

    private function guardSessionKey(): string
    {
        return 'login_keycloak-web_' . sha1(KeycloakWebGuard::class);
    }

    private function loggedInUserWithToken(?array $credentials): Authenticatable
    {
        session()->put($this->guardSessionKey(), 'user-uuid');
        if ($credentials !== null) {
            KeycloakWeb::saveToken($credentials);
        }

        return new class implements Authenticatable {
            public function getAuthIdentifierName() { return 'id'; }

            public function getAuthIdentifier() { return 'user-uuid'; }

            public function getAuthPassword() { return ''; }

            public function getAuthPasswordName() { return 'password'; }

            public function getRememberToken() { return ''; }

            public function setRememberToken($value) {}

            public function getRememberTokenName() { return ''; }
        };
    }
}
