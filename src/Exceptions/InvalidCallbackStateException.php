<?php

namespace Careerum\KeycloakWebGuard\Exceptions;

class InvalidCallbackStateException extends KeycloakCallbackException
{
    public function __construct()
    {
        parent::__construct('Invalid state');
    }
}
