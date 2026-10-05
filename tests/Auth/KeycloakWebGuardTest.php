<?php

declare(strict_types=1);

namespace Careerum\KeycloakWebGuard\Tests\Auth;

use Careerum\KeycloakWebGuard\Auth\Guard\KeycloakWebGuard;
use Careerum\KeycloakWebGuard\Facades\KeycloakWeb;
use Careerum\KeycloakWebGuard\Tests\TestCase;
use GuzzleHttp\Psr7\Response;
use Closure;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;
use Illuminate\Contracts\Cache\LockTimeoutException;
use Illuminate\Http\Request;
use Illuminate\Routing\Route;
use Illuminate\Session\ArraySessionHandler;
use Illuminate\Session\Middleware\StartSession;
use Illuminate\Session\SessionManager;
use Illuminate\Session\Store;
use PHPUnit\Framework\Attributes\DataProvider;
use Symfony\Component\HttpFoundation\Response as HttpResponse;

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
        $this->assertSame($new['refresh_token'], KeycloakWeb::retrieveToken()['refresh_token']);
        $this->assertSame('original-id-token', KeycloakWeb::retrieveToken()['id_token']);

        // A subsequent guard lookup on this same session needs no further refresh.
        $this->assertSame($user, $this->guard($user)->user());
        $this->assertSame(0, $this->mockHandler->count());
    }

    public function testBlockedRequestsReadTheRotatedTokenOnlyAfterTheFirstRequestSaves(): void
    {
        $this->assertSessionRequestOrdering(true);
    }

    public function testAPlainSessionWriterCannotRestoreAnOldRefreshToken(): void
    {
        $this->assertSessionRequestOrdering(false);
    }

    private function assertSessionRequestOrdering(bool $secondUsesGuard): void
    {
        $this->queueOpenIdConfiguration();
        $old = [
            'access_token' => $this->jwt(['exp' => time() - 60]),
            'refresh_token' => 'old-refresh-token',
            'id_token' => 'original-id-token',
        ];
        $new = $this->queueRefreshResponse();
        $handler = new ArraySessionHandler(120);
        $seed = new Store('test-session', $handler);
        $seed->start();
        $seed->put('login_keycloak-web_' . sha1(KeycloakWebGuard::class), 'user-uuid');
        $seed->put('_keycloak_token', $old);
        $seed->save();
        $sessionId = $seed->getId();

        config([
            'session.driver' => 'array',
            'session.block' => true,
            'session.block_store' => 'array',
            'session.block_wait_seconds' => 0,
            'session.cookie' => 'test-session',
            'session.lottery' => [0, 100],
        ]);
        $user = $this->loggedInUserWithToken(null);
        $sessionRequest = function (string $name, Closure $controller) use ($handler, $sessionId): HttpResponse {
            $manager = new SessionManager($this->app);
            $manager->extend('array', fn () => $handler);
            $request = Request::create('https://app.example.com/' . $name, 'POST');
            $request->cookies->set('test-session', $sessionId);
            $request->setRouteResolver(fn () => new Route('POST', '/' . $name, fn () => null));

            return (new StartSession($manager, fn () => $this->app['cache']))->handle($request, function (Request $request) use ($controller) {
                $this->app->instance('request', $request);
                $this->app->instance('session', $request->session());

                return $controller($request);
            });
        };
        $secondController = function (Request $request) use ($user, $secondUsesGuard): HttpResponse {
            if ($secondUsesGuard) {
                $this->assertSame($user, $this->guard($user)->user());
            } else {
                $request->session()->put('other-route', true);
            }

            return new HttpResponse('second');
        };

        $first = $sessionRequest('first', function () use ($user, $sessionRequest) {
            $this->assertSame($user, $this->guard($user)->user());

            try {
                $sessionRequest('blocked', function () {
                    $this->fail('A concurrent request must not reach its controller.');
                });
                $this->fail('The concurrent request should time out waiting for the session lock.');
            } catch (LockTimeoutException) {
            }

            return new HttpResponse('first');
        });
        $second = $sessionRequest('second', $secondController);

        $this->assertSame(200, $second->getStatusCode());
        $this->assertSame(200, $first->getStatusCode());
        $reloaded = new Store('test-session', $handler, $sessionId);
        $reloaded->start();
        $this->assertSame($new['access_token'], $reloaded->get('_keycloak_token')['access_token']);
        $this->assertSame($new['refresh_token'], $reloaded->get('_keycloak_token')['refresh_token']);
        $this->assertSame('user-uuid', $reloaded->get('login_keycloak-web_' . sha1(KeycloakWebGuard::class)));
        $this->assertSame(0, $this->mockHandler->count());
    }

    public function testItRefreshesAMalformedAccessTokenWithoutEmittingWarnings(): void
    {
        $credentials = $this->expiredCredentials();
        $credentials['access_token'] = 'opaque-token';
        $user = $this->loggedInUserWithToken($credentials);
        $new = $this->queueRefreshResponse();

        $this->assertSame($user, $this->guard($user)->user());
        $this->assertSame($new['access_token'], KeycloakWeb::retrieveToken()['access_token']);
    }

    public function testItDoesNotRefreshAValidToken(): void
    {
        $user = $this->loggedInUserWithToken($this->validCredentials());

        $resolved = $this->guard($user)->user();

        $this->assertSame($user, $resolved);
        $this->assertSame(0, $this->mockHandler->count());
    }

    public function testItEndsAnExpiredSessionWithoutARefreshToken(): void
    {
        $credentials = $this->expiredCredentials();
        unset($credentials['refresh_token']);
        $user = $this->loggedInUserWithToken($credentials);

        $this->assertNull($this->guard($user)->user());
        $this->assertNull(session()->get($this->guardSessionKey()));
        $this->assertNull(KeycloakWeb::retrieveToken());
        $this->assertSame(1, $this->mockHandler->count());
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

    public function testItEndsTheSessionWhenDiscoveryFails(): void
    {
        $user = $this->loggedInUserWithToken([
            'access_token' => $this->jwt(['exp' => time() - 60]),
            'refresh_token' => 'old-refresh-token',
        ]);
        $this->mockHandler->append(new \GuzzleHttp\Exception\ConnectException(
            'cURL error 7: Connection refused',
            new \GuzzleHttp\Psr7\Request('GET', self::BASE_URL . '/realms/' . self::REALM . '/.well-known/openid-configuration'),
        ));

        $this->assertNull($this->guard($user)->user());
        $this->assertNull(session()->get($this->guardSessionKey()));
        $this->assertNull(KeycloakWeb::retrieveToken());
    }

    private function expiredCredentials(): array
    {
        $this->queueOpenIdConfiguration();

        return [
            'access_token' => $this->jwt(['exp' => time() - 60]),
            'refresh_token' => 'old-refresh-token',
            'id_token' => 'original-id-token',
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
