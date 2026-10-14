<?php

declare(strict_types=1);

namespace Careerum\KeycloakWebGuard\Tests\Services;

use Careerum\KeycloakWebGuard\Services\KeycloakService;
use Careerum\KeycloakWebGuard\Facades\KeycloakWeb;
use Careerum\KeycloakWebGuard\Tests\TestCase;
use GuzzleHttp\Exception\ConnectException;
use GuzzleHttp\Exception\RequestException;
use GuzzleHttp\Psr7\Request;
use GuzzleHttp\Psr7\Response;
use Illuminate\Support\Facades\Log;
use PHPUnit\Framework\Attributes\DataProvider;
use Psr\Http\Message\RequestInterface;

class KeycloakServiceTest extends TestCase
{
    private function service(): KeycloakService
    {
        return $this->app->make(KeycloakService::class);
    }

    public function testItDiscoversTheOpenIdEndpoints(): void
    {
        $this->queueOpenIdConfiguration();

        $url = $this->service()->getLoginUrl();

        $this->assertStringStartsWith(
            self::BASE_URL . '/realms/' . self::REALM . '/protocol/openid-connect/auth?',
            $url,
        );
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        $this->assertSame('code', $query['response_type']);
        $this->assertSame(self::CLIENT_ID, $query['client_id']);
        $this->assertNotSame('', $query['state']);
    }

    public function testItExchangesTheCodeForTokens(): void
    {
        $this->queueOpenIdConfiguration();
        $this->mockHandler->append(new Response(200, [], json_encode([
            'access_token' => 'access.jwt.token',
            'refresh_token' => 'refresh-token',
            'id_token' => 'id.jwt.token',
            'expires_in' => 300,
        ])));

        $token = $this->service()->getAccessToken('auth-code');

        $request = $this->mockHandler->getLastRequest();
        $this->assertSame('POST', $request->getMethod());
        $this->assertSame(
            self::BASE_URL . '/realms/' . self::REALM . '/protocol/openid-connect/token',
            (string) $request->getUri(),
        );
        parse_str((string) $request->getBody(), $form);
        $this->assertSame('authorization_code', $form['grant_type']);
        $this->assertSame('auth-code', $form['code']);
        $this->assertSame(self::CLIENT_SECRET, $form['client_secret']);

        $this->assertSame('access.jwt.token', $token['access_token']);
        $this->assertSame('refresh-token', $token['refresh_token']);
    }

    public function testItOmitsTheClientSecretWhenNotConfigured(): void
    {
        config(['keycloak-web.client_secret' => null]);
        $this->queueOpenIdConfiguration();
        $this->mockHandler->append(new Response(200, [], json_encode(['access_token' => 'a'])));

        $this->service()->getAccessToken('auth-code');

        parse_str((string) $this->mockHandler->getLastRequest()->getBody(), $form);
        $this->assertArrayNotHasKey('client_secret', $form);
    }

    public function testItRefreshesAnExpiredAccessToken(): void
    {
        $this->queueOpenIdConfiguration();
        $this->mockHandler->append(new Response(200, [], json_encode([
            'access_token' => 'renewed.jwt.token',
            'refresh_token' => 'new-refresh-token',
            'expires_in' => 300,
        ])));

        $credentials = $this->expiredCredentials();
        $token = $this->service()->refreshAccessToken($credentials);

        $request = $this->mockHandler->getLastRequest();
        $this->assertSame(
            self::BASE_URL . '/realms/' . self::REALM . '/protocol/openid-connect/token',
            (string) $request->getUri(),
        );
        parse_str((string) $request->getBody(), $form);
        $this->assertSame('refresh_token', $form['grant_type']);
        $this->assertSame('old-refresh-token', $form['refresh_token']);

        $this->assertSame('renewed.jwt.token', $token['access_token']);
    }

    public function testItRefreshesTheTokenBeforeUserinfoWhenExpired(): void
    {
        $this->queueOpenIdConfiguration();
        $this->mockHandler->append(new Response(200, [], json_encode([
            'access_token' => 'renewed.jwt.token',
            'refresh_token' => 'new-refresh-token',
            'id_token' => $this->jwt([
                'exp' => time() + 3600,
                'aud' => self::CLIENT_ID,
                'iss' => self::BASE_URL . '/realms/' . self::REALM,
                'sub' => 'user-uuid',
            ]),
            'expires_in' => 300,
        ])));
        $this->queueUserInfo('user-uuid');

        $user = $this->service()->getUserProfile($this->expiredCredentials());

        $this->assertSame('user-uuid', $user['sub']);
        $this->assertSame($this->expiredCredentials()['id_token'], KeycloakWeb::retrieveToken()['id_token']);

        // userinfo must be fetched with the renewed access token, not the expired one
        $this->assertSame('Bearer renewed.jwt.token', $this->mockHandler->getLastRequest()->getHeaderLine('Authorization'));
    }

    public function testItFetchesTheUserProfile(): void
    {
        $credentials = $this->validCredentials();

        $this->queueOpenIdConfiguration();
        $this->queueUserInfo('user-uuid');

        $user = $this->service()->getUserProfile($credentials);

        $request = $this->mockHandler->getLastRequest();
        $this->assertSame('GET', $request->getMethod());
        $this->assertSame(
            self::BASE_URL . '/realms/' . self::REALM . '/protocol/openid-connect/userinfo',
            (string) $request->getUri(),
        );
        $this->assertSame('Bearer ' . $this->accessTokenOf($credentials), $request->getHeaderLine('Authorization'));

        $this->assertSame('user-uuid', $user['sub']);
    }

    public function testItBuildsTheLogoutUrlWithTheIdTokenHint(): void
    {
        $this->queueOpenIdConfiguration();
        session()->put(KeycloakService::KEYCLOAK_SESSION, [
            'id_token' => 'id.jwt.token',
        ]);
        config(['keycloak-web.redirect_logout' => 'https://app.example.com/logged-out']);

        $url = $this->service()->getLogoutUrl();

        $this->assertStringStartsWith(
            self::BASE_URL . '/realms/' . self::REALM . '/protocol/openid-connect/logout?',
            $url,
        );
        parse_str((string) parse_url($url, PHP_URL_QUERY), $query);
        $this->assertSame('id.jwt.token', $query['id_token_hint']);
        $this->assertSame('https://app.example.com/logged-out', $query['post_logout_redirect_uri']);
    }

    public function testItInvalidatesTheRefreshToken(): void
    {
        $this->queueOpenIdConfiguration();
        $this->mockHandler->append(new Response(204));

        $this->assertTrue($this->service()->invalidateRefreshToken('refresh-token'));

        $request = $this->mockHandler->getLastRequest();
        $this->assertSame('POST', $request->getMethod());
        $this->assertSame(
            self::BASE_URL . '/realms/' . self::REALM . '/protocol/openid-connect/logout',
            (string) $request->getUri(),
        );
        parse_str((string) $request->getBody(), $form);
        $this->assertSame('refresh-token', $form['refresh_token']);
    }

    public function testItKeepsStateValidationStrict(): void
    {
        $service = $this->service();

        $this->assertFalse($service->validateState(''));
        $this->assertFalse($service->validateState('forged'));

        $service->saveState();
        // A second instance holds a different random state than the session.
        $this->assertFalse($service->validateState('forged'));

        session()->put(KeycloakService::KEYCLOAK_SESSION_STATE, 'challenge');
        $this->assertTrue($service->validateState('challenge'));
    }

    #[DataProvider('httpFailureProvider')]
    public function testHttpFailuresAreLoggedWithoutSecrets(\Closure $failure): void
    {
        $this->queueOpenIdConfiguration([
            'token_endpoint' => self::BASE_URL . '/realms/' . self::REALM
                . '/protocol/openid-connect/token?private-query=do-not-log',
        ]);
        $this->mockHandler->append($failure);

        Log::shouldReceive('error')->once()->andReturnUsing(function (string $message, array $context = []) {
            // The rendered record must carry no request or response bodies,
            // headers, tokens or the client secret.
            $rendered = $message . ' ' . json_encode($context);
            $this->assertStringNotContainsStringIgnoringCase('client_secret', $rendered);
            $this->assertStringNotContainsStringIgnoringCase('client-secret', $rendered);
            $this->assertStringNotContainsStringIgnoringCase('authorization', $rendered);
            $this->assertStringNotContainsStringIgnoringCase('bearer', $rendered);
            $this->assertStringNotContainsStringIgnoringCase('refresh-token', $rendered);
            $this->assertStringNotContainsStringIgnoringCase('invalid_grant', $rendered);
            $this->assertStringNotContainsStringIgnoringCase('auth-code', $rendered);
            $this->assertStringNotContainsStringIgnoringCase('leaked-access-token', $rendered);
            $this->assertStringNotContainsStringIgnoringCase('do-not-log', $rendered);

            // ...but enough to act on.
            $this->assertSame(
                self::BASE_URL . '/realms/' . self::REALM . '/protocol/openid-connect/token',
                $context['request_url'],
            );
            $this->assertSame('POST', $context['request_method']);
        });

        $token = $this->service()->getAccessToken('auth-code');

        $this->assertSame([], $token);
    }

    /**
     * The failures are raised by Guzzle itself from the real token request
     * (which carries the client secret and the code), so the test covers the
     * exception shapes of whichever Guzzle major is installed.
     */
    public static function httpFailureProvider(): array
    {
        return [
            // http_errors turns this into a ClientException whose message
            // embeds a summary of the response body.
            'bad response' => [fn () => new Response(
                400,
                [],
                '{"error":"invalid_grant","error_description":"Code not valid","access_token":"leaked-access-token"}',
            )],
            'transport failure' => [fn (RequestInterface $request) => throw new ConnectException(
                'cURL error 6: Could not resolve host for ' . (string) $request->getBody(),
                $request,
            )],
        ];
    }

    public function testDiscoveryFailureThrowsWithoutLeakingTheTransportError(): void
    {
        $transportError = new ConnectException('cURL error 6: Could not resolve host', new Request('GET', 'https://keycloak.example.com/realms/test-realm/.well-known/openid-configuration'));
        $this->mockHandler->append($transportError, $transportError, $transportError);

        Log::shouldReceive('error')->times(3);
        Log::shouldReceive('warning')->once();

        try {
            $this->service()->getLoginUrl();
            $this->fail('Expected the discovery failure to throw.');
        } catch (\Exception $e) {
            $this->assertInstanceOf(\Careerum\KeycloakWebGuard\Exceptions\OpenIdConfigurationUnavailableException::class, $e);
            $this->assertSame('OpenID configuration is unavailable.', $e->getMessage());
            $this->assertStringNotContainsString('cURL error', $e->getMessage());
            // The cause stays reachable through the exception chain.
            $this->assertSame($transportError, $e->getPrevious());
        }
    }

    #[DataProvider('invalidDiscoveryProvider')]
    public function testInvalidDiscoveryIsTypedAndNeverCached(string $body): void
    {
        config(['keycloak-web.cache_openid' => true]);
        $this->mockHandler->append(new Response(200, [], $body));

        try {
            $this->service()->getLoginUrl();
            $this->fail('Invalid discovery must fail.');
        } catch (\Careerum\KeycloakWebGuard\Exceptions\InvalidOpenIdConfigurationException $e) {
            $this->assertNull($e->getPrevious());
            $this->assertSame(200, $e->getUpstreamStatus());
            $this->assertFalse($e->retryable());
        }
        $this->queueOpenIdConfiguration();
        $this->assertStringContainsString('/auth?', $this->service()->getLoginUrl());
    }

    public static function invalidDiscoveryProvider(): array
    {
        return [
            'malformed JSON' => ['{invalid'],
            'null' => ['null'],
            'array' => ['[]'],
            'missing endpoints' => ['{"issuer":"https://keycloak.example.com/realms/test-realm"}'],
            'wrong issuer' => ['{"issuer":"https://evil.example.com/realms/test-realm"}'],
        ];
    }

    public function testTransientDiscoveryRetriesOnlyTheGetAndReportsStatus(): void
    {
        $this->mockHandler->append(new Response(503), new Response(503));
        $this->queueOpenIdConfiguration();
        $this->mockHandler->append(new Response(200, [], '{"access_token":"issued"}'));
        $this->assertSame('issued', $this->service()->getAccessToken('code')['access_token']);
        $this->assertSame('POST', $this->mockHandler->getLastRequest()->getMethod());
    }

    public function testThrownTransientHttpResponseIsRetriedAndReportsStatus(): void
    {
        $request = new Request('GET', self::BASE_URL . '/realms/' . self::REALM . '/.well-known/openid-configuration');
        $this->mockHandler->append(
            RequestException::create($request, new Response(503)),
            RequestException::create($request, new Response(503)),
        );
        $this->queueOpenIdConfiguration();

        $this->assertStringContainsString('/auth?', $this->service()->getLoginUrl());
        $this->assertSame(0, $this->mockHandler->count());
    }

    public function testThrownTransientHttpResponseReportsStatusAfterRetries(): void
    {
        $request = new Request('GET', self::BASE_URL . '/realms/' . self::REALM . '/.well-known/openid-configuration');
        $this->mockHandler->append(
            RequestException::create($request, new Response(503)),
            RequestException::create($request, new Response(503)),
            RequestException::create($request, new Response(503)),
        );

        try {
            $this->service()->getLoginUrl();
            $this->fail('Expected discovery failure.');
        } catch (\Careerum\KeycloakWebGuard\Exceptions\OpenIdConfigurationUnavailableException $e) {
            $this->assertSame(503, $e->getUpstreamStatus());
            $this->assertTrue($e->retryable());
            $this->assertInstanceOf(RequestException::class, $e->getPrevious());
            $this->assertSame(0, $this->mockHandler->count());
        }
    }

    public function testNonRetryableDiscoveryStatusIsReported(): void
    {
        $this->mockHandler->append(new Response(401));
        try {
            $this->service()->getLoginUrl();
            $this->fail('Expected failure.');
        } catch (\Careerum\KeycloakWebGuard\Exceptions\OpenIdConfigurationUnavailableException $e) {
            $this->assertSame(401, $e->getUpstreamStatus());
            $this->assertSame('openid_discovery', $e->operation());
            $this->assertFalse($e->retryable());
            $this->assertSame(0, $this->mockHandler->count());
        }
    }

    public function testFreshCacheAndStaleFallback(): void
    {
        config(['keycloak-web.cache_openid' => true, 'keycloak-web.openid_fresh_ttl' => 2, 'keycloak-web.openid_stale_ttl' => 10]);
        $this->queueOpenIdConfiguration();
        $this->assertStringContainsString('/auth?', $this->service()->getLoginUrl());
        $this->assertStringContainsString('/auth?', $this->service()->getLoginUrl());
        $this->assertSame(0, $this->mockHandler->count());

        \Carbon\Carbon::setTestNow(\Carbon\Carbon::now()->addSeconds(3));
        // Cache uses real clock; override the stored fetched_at for deterministic aging.
        $key = 'keycloak_web_guard_openid_v2_' . hash('sha256', self::BASE_URL . "\0" . self::REALM);
        $entry = \Illuminate\Support\Facades\Cache::get($key);
        $entry['fetched_at'] = time() - 3;
        \Illuminate\Support\Facades\Cache::put($key, $entry, 10);
        $this->mockHandler->append(new Response(503), new Response(503), new Response(503));
        $this->assertStringContainsString('/auth?', $this->service()->getLoginUrl());
    }

    public function testStaleDiscoverySurvivesLockAcquisitionFailure(): void
    {
        config(['keycloak-web.cache_openid' => true, 'keycloak-web.openid_fresh_ttl' => 2, 'keycloak-web.openid_stale_ttl' => 10]);
        $this->queueOpenIdConfiguration();
        $this->service()->getLoginUrl();
        $key = $this->discoveryCacheKey();
        $entry = \Illuminate\Support\Facades\Cache::get($key);
        $entry['fetched_at'] = time() - 3;
        $store = \Mockery::mock();
        $store->shouldReceive('get')->once()->with($key)->andReturn($entry);
        $store->shouldReceive('lock')->once()->andThrow(new \RuntimeException('Lock backend unavailable'));
        \Illuminate\Support\Facades\Cache::shouldReceive('store')->once()->andReturn($store);

        $this->assertStringContainsString('/auth?', $this->service()->getLoginUrl());
        $this->assertSame(0, $this->mockHandler->count());
    }

    public function testStaleDiscoverySurvivesLockGetFailure(): void
    {
        config(['keycloak-web.cache_openid' => true, 'keycloak-web.openid_fresh_ttl' => 2, 'keycloak-web.openid_stale_ttl' => 10]);
        $this->queueOpenIdConfiguration();
        $this->service()->getLoginUrl();
        $key = $this->discoveryCacheKey();
        $entry = \Illuminate\Support\Facades\Cache::get($key);
        $entry['fetched_at'] = time() - 3;
        $lock = \Mockery::mock();
        $lock->shouldReceive('get')->once()->andThrow(new \RuntimeException('Lock acquisition failed'));
        $store = \Mockery::mock();
        $store->shouldReceive('get')->once()->with($key)->andReturn($entry);
        $store->shouldReceive('lock')->once()->andReturn($lock);
        \Illuminate\Support\Facades\Cache::shouldReceive('store')->once()->andReturn($store);

        $this->assertStringContainsString('/auth?', $this->service()->getLoginUrl());
        $this->assertSame(0, $this->mockHandler->count());
    }

    public function testColdDiscoveryDoesNotFetchAfterLockAcquisitionFailure(): void
    {
        config(['keycloak-web.cache_openid' => true]);
        $store = \Mockery::mock();
        $store->shouldReceive('get')->once()->andReturn(null);
        $store->shouldReceive('lock')->once()->andThrow(new \RuntimeException('Lock backend unavailable'));
        \Illuminate\Support\Facades\Cache::shouldReceive('store')->once()->andReturn($store);

        $this->expectException(\Careerum\KeycloakWebGuard\Exceptions\OpenIdConfigurationUnavailableException::class);
        try {
            $this->service()->getLoginUrl();
        } finally {
            $this->assertSame(0, $this->mockHandler->count());
        }
    }

    public function testCacheBackendFailureIsTypedAndDoesNotTriggerDiscovery(): void
    {
        config(['keycloak-web.cache_openid' => true]);
        $store = \Mockery::mock();
        $store->shouldReceive('get')->once()->andThrow(new \RuntimeException('Database unavailable'));
        \Illuminate\Support\Facades\Cache::shouldReceive('store')->once()->andReturn($store);

        try {
            $this->service()->getLoginUrl();
            $this->fail('Expected a typed cache failure.');
        } catch (\Careerum\KeycloakWebGuard\Exceptions\OpenIdConfigurationUnavailableException $e) {
            $this->assertSame('Database unavailable', $e->getPrevious()->getMessage());
            $this->assertSame(0, $this->mockHandler->count());
        }
    }

    public function testHttpIssuerIsRejectedBeforeDiscoveryRequest(): void
    {
        config(['keycloak-web.base_url' => 'http://keycloak.example.com']);
        try {
            $this->service()->getLoginUrl();
            $this->fail('An HTTP issuer must be rejected.');
        } catch (\Careerum\KeycloakWebGuard\Exceptions\InvalidOpenIdConfigurationException $e) {
            $this->assertNull($e->getUpstreamStatus());
            $this->assertSame(0, $this->mockHandler->count());
        }
    }

    public function testExplicitDefaultHttpsPortIsAllowedForEndpoints(): void
    {
        $this->queueOpenIdConfiguration([
            'token_endpoint' => 'https://keycloak.example.com:443/realms/test-realm/protocol/openid-connect/token',
        ]);

        $this->assertStringContainsString('/auth?', $this->service()->getLoginUrl());
    }

    public function testProfileReusesStaleDiscoveryAfterOneFailedRefresh(): void
    {
        config(['keycloak-web.cache_openid' => true, 'keycloak-web.openid_fresh_ttl' => 2, 'keycloak-web.openid_stale_ttl' => 10]);
        $this->queueOpenIdConfiguration();
        $this->service()->getLoginUrl();

        $key = $this->discoveryCacheKey();
        $entry = \Illuminate\Support\Facades\Cache::get($key);
        $entry['fetched_at'] = time() - 3;
        \Illuminate\Support\Facades\Cache::put($key, $entry, 10);

        $this->mockHandler->append(new Response(503), new Response(503), new Response(503));
        $this->queueUserInfo('user-uuid');
        $user = $this->service()->getUserProfile($this->validCredentials());

        $this->assertSame('user-uuid', $user['sub']);
        $this->assertSame(0, $this->mockHandler->count());
        $this->assertSame($entry['fetched_at'], \Illuminate\Support\Facades\Cache::get($key)['fetched_at']);
    }

    public function testSubclassProvidedDiscoveryIsPreservedWithoutARequest(): void
    {
        $configuration = [
            'issuer' => self::BASE_URL . '/realms/' . self::REALM,
            'authorization_endpoint' => self::BASE_URL . '/auth',
            'token_endpoint' => self::BASE_URL . '/token',
            'userinfo_endpoint' => self::BASE_URL . '/userinfo',
            'end_session_endpoint' => self::BASE_URL . '/logout',
            'jwks_uri' => self::BASE_URL . '/certs',
        ];
        $client = new \GuzzleHttp\Client(['handler' => \GuzzleHttp\HandlerStack::create($this->mockHandler)]);
        $service = new class($client, $configuration) extends KeycloakService {
            public function __construct(\GuzzleHttp\ClientInterface $client, array $configuration)
            {
                $this->openid = $configuration;
                parent::__construct($client);
            }
        };

        $this->assertStringStartsWith(self::BASE_URL . '/auth?', $service->getLoginUrl());
        $this->queueUserInfo('user-uuid');
        $this->assertSame('user-uuid', $service->getUserProfile($this->validCredentials())['sub']);
        $this->assertStringStartsWith(self::BASE_URL . '/logout?', $service->getLogoutUrl());
        $this->assertSame(0, $this->mockHandler->count());
    }

    public function testUppercaseEndpointSchemeAndHostAreAccepted(): void
    {
        $this->queueOpenIdConfiguration(['token_endpoint' => 'HTTPS://KEYCLOAK.EXAMPLE.COM/token']);
        $this->assertStringContainsString('/auth?', $this->service()->getLoginUrl());
    }

    public function testStaleDiscoveryIsNotReturnedWhenRetryCrossesHardExpiry(): void
    {
        config(['keycloak-web.cache_openid' => true, 'keycloak-web.openid_fresh_ttl' => 1, 'keycloak-web.openid_stale_ttl' => 2]);
        $this->queueOpenIdConfiguration();
        $this->service()->getLoginUrl();

        $key = $this->discoveryCacheKey();
        $entry = \Illuminate\Support\Facades\Cache::get($key);
        $entry['fetched_at'] = time() - 2;
        \Illuminate\Support\Facades\Cache::put($key, $entry, 3);
        $this->mockHandler->append(function () {
            sleep(2);
            return new Response(503);
        }, new Response(503), new Response(503));

        $this->expectException(\Careerum\KeycloakWebGuard\Exceptions\OpenIdConfigurationUnavailableException::class);
        $this->service()->getLoginUrl();
    }

    public function testNonConnectionGuzzleFailureWithoutResponseIsNotRetryable(): void
    {
        $this->mockHandler->append(new RequestException('Invalid handler request', new Request('GET', self::BASE_URL)));

        try {
            $this->service()->getLoginUrl();
            $this->fail('Expected discovery failure.');
        } catch (\Careerum\KeycloakWebGuard\Exceptions\OpenIdConfigurationUnavailableException $e) {
            $this->assertNull($e->getUpstreamStatus());
            $this->assertFalse($e->retryable());
            $this->assertSame(0, $this->mockHandler->count());
        }
    }

    public function testUncachedDiscoveryRefreshesAtProfileStartAfterFreshTtl(): void
    {
        config(['keycloak-web.openid_fresh_ttl' => 1]);
        $this->queueOpenIdConfiguration();
        $service = $this->service();
        $service->getLoginUrl();
        $fetchedAt = new \ReflectionProperty(KeycloakService::class, 'openidFetchedAt');
        $fetchedAt->setValue($service, time() - 2);

        $this->queueOpenIdConfiguration();
        $this->queueUserInfo('user-uuid');
        $user = $service->getUserProfile($this->validCredentials());

        $this->assertSame('user-uuid', $user['sub']);
        $this->assertSame(0, $this->mockHandler->count());
    }

    public function testMissingCacheStoreIsTypedAndDoesNotTriggerDiscovery(): void
    {
        config(['keycloak-web.cache_openid' => true, 'keycloak-web.openid_cache_store' => 'not-configured']);
        try {
            $this->service()->getLoginUrl();
            $this->fail('Expected a typed configuration failure.');
        } catch (\Careerum\KeycloakWebGuard\Exceptions\OpenIdConfigurationUnavailableException $e) {
            $this->assertFalse($e->retryable());
            $this->assertNull($e->getUpstreamStatus());
            $this->assertSame(0, $this->mockHandler->count());
        }
    }

    public function testHardExpiredCacheDoesNotServeStale(): void
    {
        config(['keycloak-web.cache_openid' => true, 'keycloak-web.openid_fresh_ttl' => 2, 'keycloak-web.openid_stale_ttl' => 10]);
        $this->queueOpenIdConfiguration();
        $this->service()->getLoginUrl();
        $key = $this->discoveryCacheKey();
        $entry = \Illuminate\Support\Facades\Cache::get($key);
        $entry['fetched_at'] = time() - 13;
        \Illuminate\Support\Facades\Cache::put($key, $entry, 30);
        $this->mockHandler->append(new Response(503), new Response(503), new Response(503));
        try {
            $this->service()->getLoginUrl();
            $this->fail('Hard-expired cache must not be served.');
        } catch (\Careerum\KeycloakWebGuard\Exceptions\OpenIdConfigurationUnavailableException $e) {
            $this->assertSame(503, $e->getUpstreamStatus());
            $this->assertSame($entry['fetched_at'], \Illuminate\Support\Facades\Cache::get($key)['fetched_at']);
        }
    }

    #[DataProvider('invalidEndpointProvider')]
    public function testRejectsUntrustedEndpoints(string $field, string $value): void
    {
        $this->queueOpenIdConfiguration([$field => $value]);
        $this->expectException(\Careerum\KeycloakWebGuard\Exceptions\InvalidOpenIdConfigurationException::class);
        $this->service()->getLoginUrl();
    }

    public static function invalidEndpointProvider(): array
    {
        return [
            'http endpoint' => ['token_endpoint', 'http://keycloak.example.com/token'],
            'other host' => ['userinfo_endpoint', 'https://other.example.com/userinfo'],
            'userinfo' => ['jwks_uri', 'https://user:pass@keycloak.example.com/certs'],
            'missing JWKS' => ['jwks_uri', ''],
        ];
    }

    public function testLockContentionOnColdStartNeverFetchesOutsideTheLock(): void
    {
        config(['keycloak-web.cache_openid' => true]);
        \Carbon\Carbon::setTestNow(); // Laravel's lock polling uses Carbon's clock.
        $cache = \Illuminate\Support\Facades\Cache::store();
        $lock = $cache->lock($this->discoveryCacheKey() . '_lock', 10);
        $this->assertTrue($lock->get());
        try {
            $this->expectException(\Careerum\KeycloakWebGuard\Exceptions\OpenIdConfigurationUnavailableException::class);
            $this->service()->getLoginUrl();
        } finally {
            $lock->release();
            $this->assertSame(0, $this->mockHandler->count());
        }
    }

    private function discoveryCacheKey(): string
    {
        return 'keycloak_web_guard_openid_v2_' . hash('sha256', self::BASE_URL . "\0" . self::REALM);
    }

    private function expiredCredentials(): array
    {
        return $this->credentials(time() - 60);
    }

    private function validCredentials(): array
    {
        return $this->credentials(time() + 3600);
    }

    private function credentials(int $exp): array
    {
        return [
            'access_token' => $this->jwt(['exp' => $exp]),
            'refresh_token' => 'old-refresh-token',
            'id_token' => $this->jwt([
                'exp' => time() + 3600,
                'aud' => self::CLIENT_ID,
                'iss' => self::BASE_URL . '/realms/' . self::REALM,
                'sub' => 'user-uuid',
            ]),
        ];
    }

    private function accessTokenOf(array $credentials): string
    {
        return $credentials['access_token'];
    }

    private function queueUserInfo(string $sub): void
    {
        $this->mockHandler->append(new Response(200, ['Content-Type' => 'application/json'], json_encode([
            'sub' => $sub,
            'preferred_username' => 'qa-user',
            'email' => 'qa-user@example.com',
        ])));
    }
}
