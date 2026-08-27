<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\OAuth;

/**
 * RFC 9207: add `iss` to an authorization-code redirect (query or fragment).
 *
 * League's authorize controller converts a PSR-7 302 into a generic Symfony
 * Response, so callers must apply this to the Location header rather than
 * waiting for a RedirectResponse.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9207
 */
final class AuthorizationResponseIssuer
{
    public function withIssuer(string $targetUrl, string $issuer): ?string
    {
        $parts = parse_url($targetUrl);
        if (false === $parts) {
            return null;
        }

        $query = $this->queryMap($parts['query'] ?? null);
        $fragmentRaw = $parts['fragment'] ?? null;
        $fragmentLooksLikeQuery = \is_string($fragmentRaw) && str_contains($fragmentRaw, '=');
        $fragment = $fragmentLooksLikeQuery ? $this->queryMap($fragmentRaw) : [];

        if ($this->isAuthorizationResponse($query)) {
            return $this->rebuild($parts, $this->withIss($query, $issuer), $fragmentLooksLikeQuery ? $fragmentRaw : ($parts['fragment'] ?? null));
        }

        if ($this->isAuthorizationResponse($fragment)) {
            return $this->rebuild($parts, $parts['query'] ?? null, http_build_query($this->withIss($fragment, $issuer), '', '&', \PHP_QUERY_RFC3986));
        }

        return null;
    }

    /**
     * @param array<string, mixed> $params
     *
     * @return array<string, mixed>
     */
    private function withIss(array $params, string $issuer): array
    {
        if (!isset($params['iss']) || !\is_string($params['iss']) || '' === $params['iss']) {
            $params['iss'] = $issuer;
        }

        return $params;
    }

    /**
     * @param array<string, mixed> $params
     */
    private function isAuthorizationResponse(array $params): bool
    {
        return $this->nonEmptyString($params, 'code') || $this->nonEmptyString($params, 'error');
    }

    /**
     * @param array<string, mixed> $params
     */
    private function nonEmptyString(array $params, string $key): bool
    {
        return isset($params[$key]) && \is_string($params[$key]) && '' !== $params[$key];
    }

    /**
     * @return array<string, mixed>
     */
    private function queryMap(?string $query): array
    {
        if (null === $query || '' === $query) {
            return [];
        }

        $params = [];
        parse_str($query, $params);

        return $params;
    }

    /**
     * @param array<string, mixed> $parts
     * @param array<string, mixed>|string|null $query
     */
    private function rebuild(array $parts, array|string|null $query, ?string $fragment): string
    {
        $scheme = isset($parts['scheme']) ? $parts['scheme'].'://' : '';
        $user = $parts['user'] ?? '';
        $pass = isset($parts['pass']) ? ':'.$parts['pass'] : '';
        $auth = '' !== $user ? $user.$pass.'@' : '';
        $host = $parts['host'] ?? '';
        $port = isset($parts['port']) ? ':'.$parts['port'] : '';
        $path = $parts['path'] ?? '';

        if (\is_array($query)) {
            $queryString = [] === $query ? '' : '?'.http_build_query($query, '', '&', \PHP_QUERY_RFC3986);
        } elseif (\is_string($query) && '' !== $query) {
            $queryString = '?'.$query;
        } else {
            $queryString = '';
        }

        $fragmentString = \is_string($fragment) && '' !== $fragment ? '#'.$fragment : '';

        return $scheme.$auth.$host.$port.$path.$queryString.$fragmentString;
    }
}
