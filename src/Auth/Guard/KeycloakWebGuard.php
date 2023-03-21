<?php

namespace Careerum\KeycloakWebGuard\Auth\Guard;

use Careerum\KeycloakWebGuard\Services\KeycloakService;
use Illuminate\Contracts\Auth\Authenticatable;
use Illuminate\Contracts\Auth\StatefulGuard;
use Illuminate\Contracts\Session\Session;
use Illuminate\Http\Request;
use Illuminate\Support\Facades\Config;
use Careerum\KeycloakWebGuard\Auth\KeycloakAccessToken;
use Careerum\KeycloakWebGuard\Exceptions\KeycloakCallbackException;
use Careerum\KeycloakWebGuard\Models\KeycloakUser;
use Careerum\KeycloakWebGuard\Facades\KeycloakWeb;
use Illuminate\Contracts\Auth\UserProvider;

class KeycloakWebGuard implements StatefulGuard
{/**
     * @var null|Authenticatable
     */
    protected $user;

    protected string $sessionName;
    protected UserProvider $provider;
    protected Request $request;

    /**
     * Constructor.
     *
     * @param Request $request
     */
    public function __construct(string $sessionName, UserProvider $provider, Request $request)
    {
        $this->sessionName = $sessionName;
        $this->provider = $provider;
        $this->request = $request;
    }

    /**
     * Determine if the current user is authenticated.
     *
     * @return bool
     */
    public function check()
    {
        return (bool) $this->user();
    }
    
    public function hasUser()
    {
        return (bool) $this->user();
    }

    /**
     * Determine if the current user is a guest.
     *
     * @return bool
     */
    public function guest()
    {
        return ! $this->check();
    }

    /**
     * Get the currently authenticated user.
     *
     * @return \Illuminate\Contracts\Auth\Authenticatable|null
     */
    public function user()
    {
        if (!is_null($this->user)) {
            return $this->user;
        }

        $this->authenticateFromSession();

        if (empty($this->user)) {
            $this->authenticateViaKeycloak();
        }

        return $this->user;
    }

    /**
     * Set the current user.
     *
     * @param  \Illuminate\Contracts\Auth\Authenticatable  $user
     * @return void
     */
    public function setUser(?Authenticatable $user)
    {
        $this->user = $user;
    }

    /**
     * Get the ID for the currently authenticated user.
     *
     * @return int|string|null
     */
    public function id()
    {
        $user = $this->user();
        return $user->id ?? null;
    }

    /**
     * Validate a user's credentials.
     *
     * @param  array  $credentials
     *
     * @throws BadMethodCallException
     *
     * @return bool
     */
    public function validate(array $credentials = [])
    {
        if (empty($credentials['access_token']) || empty($credentials['id_token'])) {
            return false;
        }

        /**
         * Store the section
         */
        $credentials['refresh_token'] = $credentials['refresh_token'] ?? '';
        KeycloakWeb::saveToken($credentials);

        return $this->authenticateViaKeycloak();
    }

    public function logout()
    {
        $this->request->session()->remove($this->getSessionName());
        KeycloakWeb::forgetToken();

        $this->user = null;
    }

    /**
     * Try to authenticate the user
     *
     * @throws KeycloakCallbackException
     * @return boolean
     */
    public function authenticateViaKeycloak()
    {
        // Get Credentials
        $tokenCredentials = KeycloakWeb::retrieveToken();
        if (empty($tokenCredentials)) {
            return false;
        }

        $userCredentials = KeycloakWeb::getUserProfile($tokenCredentials);
        if (empty($userCredentials)) {
            KeycloakWeb::forgetToken();

            if (Config::get('app.debug', false)) {
                throw new KeycloakCallbackException('User cannot be authenticated.');
            }

            return false;
        }

        return $this->attempt($userCredentials);
    }
    
    /**
     * Check user is authenticated and return his resource roles
     *
     * @param string $resource Default is empty: point to client_id
     *
     * @return array
    */
    public function roles($resource = '')
    {
        if (empty($resource)) {
            $resource = Config::get('keycloak-web.client_id');
        }

        if (! $this->check()) {
            return false;
        }

        $token = KeycloakWeb::retrieveToken();

        if (empty($token) || empty($token['access_token'])) {
            return false;
        }

        $token = new KeycloakAccessToken($token);
        $token = $token->parseAccessToken();

        $resourceRoles = $token['resource_access'] ?? [];
        $resourceRoles = $resourceRoles[ $resource ] ?? [];
        $resourceRoles = $resourceRoles['roles'] ?? [];

        return $resourceRoles;
    }

    /**
     * Check user has a role
     *
     * @param array|string $roles
     * @param string $resource Default is empty: point to client_id
     *
     * @return boolean
     */
    public function hasRole($roles, $resource = '')
    {
        return empty(array_diff((array) $roles, $this->roles($resource)));
    }

    /**
     * Try to authenticate the user from session
     *
     * @return KeycloakUser|Authenticatable|null
     */
    protected function authenticateFromSession()
    {
        $id = $this->request->session()->get($this->getSessionName());
        if (!is_null($id)) {
            $this->user = $this->provider->retrieveById($id);
        }

        return $this->user;
    }

    public function getSessionName(): string
    {
        return 'login_' . $this->sessionName . '_' . sha1(static::class);
    }

    public function attempt(array $credentials = [], $remember = false)
    {
        $user = $this->provider->retrieveByCredentials($credentials);

        if (is_null($user)) {
            return false;
        }

        $this->login($user, $remember);

        return true;
    }

    public function once(array $credentials = [])
    {
        if ($this->validate($credentials)) {
            $this->setUser($this->lastAttempted);

            return true;
        }

        return false;
    }

    public function login(Authenticatable $user, $remember = false)
    {
        $this->updateSession($user->getAuthIdentifier());

        $this->setUser($user);
    }

    public function loginUsingId($id, $remember = false)
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {
            $this->login($user, $remember);

            return $user;
        }

        return false;
    }

    public function onceUsingId($id)
    {
        if (!is_null($user = $this->provider->retrieveById($id))) {
            $this->setUser($user);

            return $user;
        }

        return false;
    }

    public function viaRemember()
    {
        throw new \BadMethodCallException('Unexpected method [viaRemember] call');
    }

    protected function updateSession(string $id)
    {
        $this->request->session()->put($this->getSessionName(), $id);
    }
}
