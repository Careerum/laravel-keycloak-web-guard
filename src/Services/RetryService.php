<?php

namespace Careerum\KeycloakWebGuard\Services;

use Careerum\KeycloakWebGuard\Exceptions\KeycloakCallbackException;
use Careerum\KeycloakWebGuard\Facades\KeycloakWeb;
use Illuminate\Http\RedirectResponse;

class RetryService
{
    const RETRY_LOGIN_QUERY_NAME = 'retry_login';

    /**
     * @return RedirectResponse
     *
     * @throws KeycloakCallbackException
     */
    public function retry(): RedirectResponse
    {
        $currentRedirectUrl = $this->getRedirectUrl();
        $query = $this->getQuery($currentRedirectUrl);
        $this->canRetry($query);
        $redirectUrl = $this->buildRedirectUrlForRetry($currentRedirectUrl);
        KeycloakWeb::forgetState();

        return redirect($redirectUrl);
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
        if (isset($query[self::RETRY_LOGIN_QUERY_NAME])) {
            KeycloakWeb::forgetState();

            throw new KeycloakCallbackException('Invalid state');
        }
    }

    private function buildRedirectUrlForRetry(string $url): string
    {
        $parsedUrl = parse_url($url);
        parse_str($parsedUrl['query'] ?? '', $parsedQuery);
        $parsedQuery[self::RETRY_LOGIN_QUERY_NAME] = 1;
        $parsedUrl['query'] = http_build_query($parsedQuery);

        $scheme = isset($parsedUrl['scheme']) ? "{$parsedUrl['scheme']}://" : '';
        $host = $parsedUrl['host'] ?? '';
        $path = $parsedUrl['path'] ?? '';

        return "{$scheme}{$host}{$path}?{$parsedUrl['query']}";
    }
}