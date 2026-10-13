<?php

namespace Careerum\KeycloakWebGuard\Exceptions;

use RuntimeException;

/** The OpenID discovery document could not be safely obtained. */
class OpenIdConfigurationUnavailableException extends RuntimeException
{
    public function __construct(
        ?\Throwable $previous = null,
        private readonly ?int $upstreamStatus = null,
        private readonly bool $retryable = true,
    ) {
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
