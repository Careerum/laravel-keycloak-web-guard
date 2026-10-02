<?php

declare(strict_types=1);

namespace Careerum\KeycloakWebGuard\Tests;

use Carbon\Carbon;
use GuzzleHttp\Client;
use GuzzleHttp\Handler\MockHandler;
use GuzzleHttp\HandlerStack;
use GuzzleHttp\Psr7\Response;
use Orchestra\Testbench\TestCase as TestbenchTestCase;

/**
 * Boots the package through its real service provider inside a minimal
 * Laravel app, with a Guzzle MockHandler substituted for the HTTP client.
 */
abstract class TestCase extends TestbenchTestCase
{
    protected const BASE_URL = 'https://keycloak.example.com';
    protected const REALM = 'test-realm';
    protected const CLIENT_ID = 'test-client';
    protected const CLIENT_SECRET = 'test-client-secret';

    protected MockHandler $mockHandler;

    protected function getPackageProviders($app): array
    {
        return [\Careerum\KeycloakWebGuard\KeycloakWebGuardServiceProvider::class];
    }

    protected function defineEnvironment($app): void
    {
        $app['config']->set('keycloak-web.base_url', self::BASE_URL);
        $app['config']->set('keycloak-web.realm', self::REALM);
        $app['config']->set('keycloak-web.client_id', self::CLIENT_ID);
        $app['config']->set('keycloak-web.client_secret', self::CLIENT_SECRET);
        $app['config']->set('keycloak-web.cache_openid', false);
    }

    protected function setUp(): void
    {
        parent::setUp();

        Carbon::setTestNow(Carbon::now());

        $this->mockHandler = new MockHandler();
        $client = new Client(['handler' => HandlerStack::create($this->mockHandler)]);

        // The service provider binds the HTTP client contextually, so a plain
        // container instance is not enough — rebind the same way.
        $this->app->when(\Careerum\KeycloakWebGuard\Services\KeycloakService::class)
            ->needs(\GuzzleHttp\ClientInterface::class)
            ->give(fn () => $client);
    }

    protected function tearDown(): void
    {
        Carbon::setTestNow();

        parent::tearDown();
    }

    /**
     * Enqueues the .well-known/openid-configuration discovery response.
     */
    protected function queueOpenIdConfiguration(array $overrides = []): void
    {
        $this->mockHandler->append(new Response(200, ['Content-Type' => 'application/json'], json_encode(array_merge([
            'issuer' => self::BASE_URL . '/realms/' . self::REALM,
            'authorization_endpoint' => self::BASE_URL . '/realms/' . self::REALM . '/protocol/openid-connect/auth',
            'token_endpoint' => self::BASE_URL . '/realms/' . self::REALM . '/protocol/openid-connect/token',
            'userinfo_endpoint' => self::BASE_URL . '/realms/' . self::REALM . '/protocol/openid-connect/userinfo',
            'end_session_endpoint' => self::BASE_URL . '/realms/' . self::REALM . '/protocol/openid-connect/logout',
        ], $overrides))));
    }

    /**
     * An unsigned JWT; the guard's parser base64-decodes the payload only.
     */
    protected function jwt(array $payload): string
    {
        $segment = fn (array $data) => rtrim(strtr(base64_encode(json_encode($data)), '+/', '-_'), '=');

        return $segment(['alg' => 'none']) . '.' . $segment($payload) . '.';
    }
}
