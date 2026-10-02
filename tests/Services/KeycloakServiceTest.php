<?php

declare(strict_types=1);

namespace Careerum\KeycloakWebGuard\Tests\Services;

use Careerum\KeycloakWebGuard\Services\KeycloakService;
use Careerum\KeycloakWebGuard\Tests\TestCase;
use GuzzleHttp\Exception\ConnectException;
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
        $this->mockHandler->append(new ConnectException('cURL error 6: Could not resolve host', new Request('GET', 'https://keycloak.example.com/realms/test-realm/.well-known/openid-configuration')));

        Log::shouldReceive('error')->once();

        $this->expectException(\Exception::class);
        $this->expectExceptionMessage('It was not possible to load OpenId configuration');

        $this->service()->getLoginUrl();
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
