<?php

namespace Careerum\KeycloakWebGuard\Middleware;

use Closure;
use Illuminate\Auth\Middleware\Authenticate;

class KeycloakAuthenticated extends Authenticate
{
    public function handle($request, Closure $next, ...$guards)
    {
        $excludedRoutes = [
            route('keycloak.login', [],false),
            route('keycloak.callback', [],false),
        ];
        $requestPath = '/' . $request->path();
        foreach ($excludedRoutes as $excludedRoute) {
            if ($requestPath === $excludedRoute) {
                \Log::debug("Skipping {$excludedRoute} from auth check...");
                return $next($request);
            }
        }

        return parent::handle($request, $next, $guards);
    }

    /**
     * Redirect user if it's not authenticated.
     *
     * @param  \Illuminate\Http\Request  $request
     * @return string
     */
    protected function redirectTo($request)
    {
        return route('keycloak.login');
    }

    protected function unauthenticated($request, array $guards)
    {
        $excludedRoutes = [
            route('keycloak.login'),
            route('keycloak.callback'),
        ];
        $url = request()->url();
        if (!in_array($url, $excludedRoutes)) {
            redirect()->setIntendedUrl($url);
        }

        parent::unauthenticated($request, $guards);
    }
}
