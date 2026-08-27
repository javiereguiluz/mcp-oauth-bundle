<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\OAuth;

use Omouren\McpOauthBundle\McpOauthSettings;
use Symfony\Component\HttpFoundation\Request;

/**
 * Listeners call this before touching a request: MCP HTTP path, or
 * authorize/token that actually targets MCP. Anything else is left alone.
 *
 * @see https://modelcontextprotocol.io/specification/2026-07-28/basic/authorization
 */
final readonly class McpRequestGuard
{
    public function __construct(
        private McpOauthSettings $settings,
        private IssuerResolver $issuerResolver,
        private CanonicalResourceUri $canonicalResourceUri,
    ) {
    }

    public function isResourcePath(Request $request): bool
    {
        return $this->pathEquals($request->getPathInfo(), $this->settings->resourcePath);
    }

    public function isAuthorizePath(Request $request): bool
    {
        return $this->pathEquals($request->getPathInfo(), $this->authorizePath());
    }

    public function isTokenPath(Request $request): bool
    {
        return $this->pathEquals($request->getPathInfo(), $this->tokenPath());
    }

    public function isMcpAuthorize(Request $request): bool
    {
        return $this->isAuthorizePath($request) && $this->targetsMcp($request);
    }

    /**
     * @param iterable<mixed> $scopes
     */
    public function isMcpToken(Request $request, iterable $scopes = []): bool
    {
        return $this->isTokenPath($request) && $this->targetsMcp($request, $scopes);
    }

    /**
     * @param iterable<mixed> $scopes
     */
    public function targetsMcp(Request $request, iterable $scopes = []): bool
    {
        $resource = $this->resourceParameter($request);
        if (null !== $resource) {
            return $this->canonicalResourceUri->matches(
                $this->issuerResolver->resource($request),
                $resource,
            );
        }

        return $this->scopesIncludeMcp($scopes) || $this->scopesIncludeMcp($this->requestedScopes($request));
    }

    /**
     * @param iterable<mixed> $scopes
     */
    public function scopesIncludeMcp(iterable $scopes): bool
    {
        foreach ($scopes as $scope) {
            $name = $this->scopeName($scope);
            if (null !== $name && \in_array($name, $this->settings->scopes, true)) {
                return true;
            }
        }

        return false;
    }

    private function authorizePath(): string
    {
        return rtrim($this->settings->authorizationPrefix, '/').'/authorize';
    }

    private function tokenPath(): string
    {
        return rtrim($this->settings->authorizationPrefix, '/').'/token';
    }

    private function pathEquals(string $pathInfo, string $expected): bool
    {
        return $this->normalizePath($pathInfo) === $this->normalizePath($expected);
    }

    private function normalizePath(string $path): string
    {
        $normalized = rtrim($path, '/');

        return '' === $normalized ? '/' : $normalized;
    }

    private function resourceParameter(Request $request): ?string
    {
        $value = $request->query->get('resource') ?? $request->request->get('resource');

        return \is_string($value) && '' !== $value ? $value : null;
    }

    /**
     * @return list<string>
     */
    private function requestedScopes(Request $request): array
    {
        $raw = $request->query->get('scope') ?? $request->request->get('scope');
        if (!\is_string($raw) || '' === trim($raw)) {
            return [];
        }

        $parts = preg_split('/\s+/', trim($raw));

        return false === $parts ? [] : array_values(array_filter($parts, static fn (string $scope): bool => '' !== $scope));
    }

    private function scopeName(mixed $scope): ?string
    {
        if (\is_string($scope) && '' !== $scope) {
            return $scope;
        }

        if (\is_object($scope) && method_exists($scope, 'getIdentifier')) {
            $identifier = $scope->getIdentifier();
            if (\is_string($identifier) && '' !== $identifier) {
                return $identifier;
            }
        }

        if (\is_object($scope) && method_exists($scope, '__toString')) {
            $name = (string) $scope;

            return '' !== $name ? $name : null;
        }

        return null;
    }
}
