<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\OAuth;

use Omouren\McpOauthBundle\McpOauthSettings;
use Symfony\Component\HttpFoundation\Request;

/**
 * Resolves OAuth issuer, MCP resource URI, and well-known metadata URLs.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8414
 * @see https://datatracker.ietf.org/doc/html/rfc9728
 */
final readonly class IssuerResolver
{
    public function __construct(
        private McpOauthSettings $settings,
        private CanonicalResourceUri $canonicalResourceUri,
    ) {
    }

    public function issuer(Request $request): string
    {
        if (null !== $this->settings->publicBaseUrl && '' !== $this->settings->publicBaseUrl) {
            return rtrim($this->settings->publicBaseUrl, '/');
        }

        return $request->getSchemeAndHttpHost();
    }

    public function resource(Request $request): string
    {
        return $this->canonicalResourceUri->combine($this->issuer($request), $this->settings->resourcePath);
    }

    public function authorizationServerMetadataUrl(Request $request): string
    {
        return $this->issuer($request).'/.well-known/oauth-authorization-server';
    }

    public function protectedResourceMetadataUrl(Request $request): string
    {
        $suffix = trim($this->settings->resourcePath, '/');
        $url = $this->issuer($request).'/.well-known/oauth-protected-resource';
        if ('' !== $suffix) {
            $url .= '/'.$suffix;
        }

        return $url;
    }

    public function authorizeUrl(Request $request): string
    {
        return $this->issuer($request).rtrim($this->settings->authorizationPrefix, '/').'/authorize';
    }

    public function tokenUrl(Request $request): string
    {
        return $this->issuer($request).rtrim($this->settings->authorizationPrefix, '/').'/token';
    }

    public function registrationUrl(Request $request): string
    {
        return $this->issuer($request).rtrim($this->settings->authorizationPrefix, '/').'/register';
    }
}
