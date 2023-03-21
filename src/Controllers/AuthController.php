<?php

namespace Careerum\KeycloakWebGuard\Controllers;

use Careerum\KeycloakWebGuard\Services\RetryService;
use Illuminate\Http\RedirectResponse;
use Illuminate\Http\Request;
use Illuminate\Routing\Controller;
use Illuminate\Support\Facades\Auth;
use Careerum\KeycloakWebGuard\Exceptions\KeycloakCallbackException;
use Careerum\KeycloakWebGuard\Facades\KeycloakWeb;

class AuthController extends Controller
{
    private RetryService $retryService;

    public function __construct(RetryService $retryService)
    {
        $this->retryService = $retryService;
    }

    /**
     * Redirect to login
     *
     * @return view
     */
    public function login()
    {
        $url = KeycloakWeb::getLoginUrl();
        KeycloakWeb::saveState();

        return redirect($url);
    }

    /**
     * Redirect to logout
     *
     * @return view
     */
    public function logout()
    {
        $url = KeycloakWeb::getLogoutUrl();
        Auth::logout();
        return redirect($url);
    }

    /**
     * Keycloak callback page
     *
     * @throws KeycloakCallbackException
     *
     * @return view|RedirectResponse
     */
    public function callback(Request $request)
    {
        // Check for errors from Keycloak
        if (! empty($request->input('error'))) {
            $error = $request->input('error_description');
            $error = ($error) ?: $request->input('error');

            throw new KeycloakCallbackException($error);
        }

        // Check given state to mitigate CSRF attack
        $state = $request->input('state');
        if (empty($state) || ! KeycloakWeb::validateState($state)) {
            return $this->retryService->retry();
        }

        // Change code for token
        $code = $request->input('code');
        if (! empty($code)) {
            $token = KeycloakWeb::getAccessToken($code);

            if (Auth::validate($token)) {
                $url = config('keycloak-web.redirect_url', '/admin');
                return redirect()->intended($url);
            }
        }

        return redirect(route('keycloak.login'));
    }
}
