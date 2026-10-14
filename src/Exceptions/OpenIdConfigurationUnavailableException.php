<?php

namespace Careerum\KeycloakWebGuard\Exceptions;

use RuntimeException;

/** The OpenID discovery document could not be safely obtained. */
class OpenIdConfigurationUnavailableException extends RuntimeException
{
    private ?int $upstreamStatus;
    private bool $retryable;

    public function __construct(?\Throwable $previous = null, ?int $upstreamStatus = null, bool $retryable = true)
    {
        $this->upstreamStatus = $upstreamStatus;
        $this->retryable = $retryable;
        // Keep the transport cause for callers; sanitize it at telemetry boundaries.
        parent::__construct('OpenID configuration is unavailable.', 0, $previous);
    }

    public function getUpstreamStatus(): ?int
    {
        return $this->upstreamStatus;
    }

    public function operation(): string
    {
        return 'openid_discovery';
    }

    public function retryable(): bool
    {
        return $this->retryable;
    }
}
