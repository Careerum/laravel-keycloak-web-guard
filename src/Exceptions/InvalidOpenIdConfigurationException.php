<?php

namespace Careerum\KeycloakWebGuard\Exceptions;

class InvalidOpenIdConfigurationException extends OpenIdConfigurationUnavailableException
{
    public function __construct(?\Throwable $previous = null)
    {
        parent::__construct($previous, 200, false);
    }
}
