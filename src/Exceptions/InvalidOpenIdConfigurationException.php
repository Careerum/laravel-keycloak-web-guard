<?php

namespace Careerum\KeycloakWebGuard\Exceptions;

class InvalidOpenIdConfigurationException extends OpenIdConfigurationUnavailableException
{
    public function __construct(?\Throwable $previous = null, ?int $upstreamStatus = null)
    {
        parent::__construct($previous, $upstreamStatus, false);
    }
}
