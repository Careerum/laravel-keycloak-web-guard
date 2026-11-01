<?php

namespace Careerum\KeycloakWebGuard\Services;

use Careerum\KeycloakWebGuard\Exceptions\InvalidCallbackStateException;
use Careerum\KeycloakWebGuard\Facades\KeycloakWeb;
use Illuminate\Http\RedirectResponse;

class RetryService
{
    const RETRY_LOGIN_QUERY_NAME = 'retry_login';
    const RETRY_LOGIN_TIMEOUT = 30;
    private const RETRY_LOGIN_SESSION_NAME = '_keycloak_retry_login';

    /**
     * @return RedirectResponse
     *
     * @throws InvalidCallbackStateException
     */
    public function retry(): RedirectResponse
    {
        $currentRedirectUrl = $this->getRedirectUrl();
        $query = $this->getQuery($currentRedirectUrl);
        $this->canRetry($query);
        $redirectUrl = $this->buildRedirectUrlForRetry($currentRedirectUrl);
        session()->put(self::RETRY_LOGIN_SESSION_NAME, time());
        KeycloakWeb::forgetState();

        return redirect($redirectUrl);
    }

    public function clearRetry(): void
    {
        session()->forget(self::RETRY_LOGIN_SESSION_NAME);
    }

    private function getRedirectUrl(): string
    {
        $url = redirect()->getIntendedUrl();

        return $url ?? config('keycloak-web.redirect_url', '/admin');
    }

    private function getQuery(string $url): array
    {
        $queryString = parse_url($url, PHP_URL_QUERY);
        if (!$queryString) {
            return [];
        }
        parse_str($queryString, $query);

        return $query;
    }

    private function canRetry(array $query): void
    {
        $lastRetry = session()->get(self::RETRY_LOGIN_SESSION_NAME);
        $retryInUrl = $query[self::RETRY_LOGIN_QUERY_NAME] ?? null;

        if ((is_numeric($lastRetry) && time() - $lastRetry < self::RETRY_LOGIN_TIMEOUT)
            || (is_numeric($retryInUrl) && $retryInUrl <= time()
                && time() - $retryInUrl < self::RETRY_LOGIN_TIMEOUT)) {
            KeycloakWeb::forgetState();

            throw new InvalidCallbackStateException();
        }
    }

    private function buildRedirectUrlForRetry(string $url): string
    {
        $parsedUrl = parse_url($url);
        parse_str($parsedUrl['query'] ?? '', $parsedQuery);
        $parsedQuery[self::RETRY_LOGIN_QUERY_NAME] = time();
        $parsedUrl['query'] = http_build_query($parsedQuery);

        $scheme = isset($parsedUrl['scheme']) ? "{$parsedUrl['scheme']}://" : '';
        $host = $parsedUrl['host'] ?? '';
        $path = $parsedUrl['path'] ?? '';

        return "{$scheme}{$host}{$path}?{$parsedUrl['query']}";
    }
}