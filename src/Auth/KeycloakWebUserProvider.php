<?php

namespace Careerum\KeycloakWebGuard\Auth;

use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\UserProvider;

class KeycloakWebUserProvider implements UserProvider
{
    /**
     * The user model path
     * @var string
     */
    protected string $model;

    /**
     * User model search field
     *
     * @var string
     */
    protected string $userSearchField;

    /**
     * Key cloak user id field
     * @var string
     */
    protected string $keyCloakSearchField;

    /**
     * The user creator class path
     * @var string
     */
    protected string $userCreator;

    /**
     * The user sync class path
     * @var string
     */
    protected string $syncUser;

    public function __construct(
        string $model,
        string $userSearchField,
        string $keyCloakSearchField,
        string $userCreator,
        string $syncUser
    ) {
        $this->model = $model;
        $this->userSearchField = $userSearchField;
        $this->keyCloakSearchField = $keyCloakSearchField;
        $this->userCreator = $userCreator;
        $this->syncUser = $syncUser;
    }

    /**
     * Retrieve a user by the given credentials.
     *
     * @param  array  $credentials
     * @return Authenticatable|null
     */
    public function retrieveByCredentials(array $credentials): ?Authenticatable
    {
        if (!$this->validateCredentialsData($credentials)) {
            return null;
        }

        $user = $this->getUser($credentials);
        if (!$user) {
            return null;
        }

        return $this->syncUser($user, $credentials);
    }

    /**
     * Retrieve a user by their unique identifier.
     *
     * @param  mixed  $identifier
     * @return Authenticatable|null
     */
    public function retrieveById($identifier)
    {
        $class = '\\' . ltrim($this->model, '\\');
        $classObject = new $class;

        return $class::where($classObject->getAuthIdentifierName(), $identifier)->first();
    }

    /**
     * Retrieve a user by their unique identifier and "remember me" token.
     *
     * @param  mixed  $identifier
     * @param  string  $token
     * @return Authenticatable|null
     */
    public function retrieveByToken($identifier, $token)
    {
        throw new \BadMethodCallException('Unexpected method [retrieveByToken] call');
    }

    /**
     * Update the "remember me" token for the given user in storage.
     *
     * @param Authenticatable $user
     * @param  string  $token
     * @return void
     */
    public function updateRememberToken(Authenticatable $user, $token)
    {
        throw new \BadMethodCallException('Unexpected method [updateRememberToken] call');
    }

    /**
     * Validate a user against the given credentials.
     *
     * @param Authenticatable $user
     * @param  array  $credentials
     * @return bool
     */
    public function validateCredentials(Authenticatable $user, array $credentials)
    {
        throw new \BadMethodCallException('Unexpected method [validateCredentials] call');
    }

    private function validateCredentialsData(array $credentials): bool
    {
        return isset($credentials[$this->keyCloakSearchField]);
    }

    private function createUser(array $credentials): ?Authenticatable
    {
        /** @var Object $userCreatorClass */
        $userCreatorClass = '\\' . ltrim($this->userCreator, '\\');
        $userCreator = new $userCreatorClass();

        return $userCreator::createUser($credentials);
    }

    private function getUser(array $credentials): ?Authenticatable
    {
        $class = '\\' . ltrim($this->model, '\\');

        return $class::where($this->userSearchField, $credentials[$this->keyCloakSearchField])
            ->firstOr(function () use ($credentials) {
                return $this->createUser($credentials);
            });
    }

    private function syncUser(Authenticatable $user, array $credentials): Authenticatable
    {
        /** @var Object $userCreatorClass */
        $syncUserClass = '\\' . ltrim($this->syncUser, '\\');
        $syncUser = new $syncUserClass();

        return $syncUser->sync($user, $credentials);
    }
}
