<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\OAuth;

use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\CanonicalResourceUri;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

final class McpRequestGuardTest extends TestCase
{
    public function testResourcePathIsExact(): void
    {
        $guard = $this->guard();

        self::assertTrue($guard->isResourcePath(Request::create('https://mcp.example.test/_mcp')));
        self::assertTrue($guard->isResourcePath(Request::create('https://mcp.example.test/_mcp/')));
        self::assertFalse($guard->isResourcePath(Request::create('https://mcp.example.test/_mcp-admin')));
        self::assertFalse($guard->isResourcePath(Request::create('https://mcp.example.test/login')));
    }

    public function testAuthorizePathIsExact(): void
    {
        $guard = $this->guard();

        self::assertTrue($guard->isAuthorizePath(Request::create('https://mcp.example.test/oauth2/authorize')));
        self::assertFalse($guard->isAuthorizePath(Request::create('https://mcp.example.test/oauth2/authorize-extra')));
        self::assertFalse($guard->isAuthorizePath(Request::create('https://mcp.example.test/oauth2/token')));
    }

    public function testMcpAuthorizeRequiresScopeOrMatchingResource(): void
    {
        $guard = $this->guard();

        self::assertTrue($guard->isMcpAuthorize(Request::create('https://mcp.example.test/oauth2/authorize?scope=mcp')));
        self::assertTrue($guard->isMcpAuthorize(Request::create(
            'https://mcp.example.test/oauth2/authorize?resource=https://mcp.example.test/_mcp',
        )));
        self::assertFalse($guard->isMcpAuthorize(Request::create('https://mcp.example.test/oauth2/authorize')));
        self::assertFalse($guard->isMcpAuthorize(Request::create(
            'https://mcp.example.test/oauth2/authorize?scope=mcp&resource=https://other.example/api',
        )));
    }

    public function testMcpTokenUsesBodyScopeWhenResourceIsAbsent(): void
    {
        $guard = $this->guard();
        $request = Request::create('https://mcp.example.test/oauth2/token', 'POST', [
            'scope' => 'mcp',
        ]);

        self::assertTrue($guard->isMcpToken($request));
        self::assertFalse($guard->isMcpToken(Request::create('https://mcp.example.test/oauth2/token', 'POST')));
        self::assertTrue($guard->isMcpToken(
            Request::create('https://mcp.example.test/oauth2/token', 'POST'),
            ['mcp'],
        ));
    }

    public function testForeignResourceIsNotMcpEvenWithMcpScope(): void
    {
        $request = Request::create('https://mcp.example.test/oauth2/token', 'POST', [
            'scope' => 'mcp',
            'resource' => 'https://other.example/api',
        ]);

        self::assertFalse($this->guard()->isMcpToken($request));
    }

    public function testIsolationUsesConfiguredScopes(): void
    {
        $guard = $this->guard(scopes: ['tools']);

        self::assertTrue($guard->isMcpAuthorize(Request::create('https://mcp.example.test/oauth2/authorize?scope=tools')));
        self::assertFalse($guard->isMcpAuthorize(Request::create('https://mcp.example.test/oauth2/authorize?scope=mcp')));
    }

    public function testResourcePathMatchesAnyConfiguredHttpPath(): void
    {
        $guard = $this->guard(resourcePaths: ['/_mcp', '/mcp/editors']);

        self::assertTrue($guard->isResourcePath(Request::create('https://mcp.example.test/_mcp')));
        self::assertTrue($guard->isResourcePath(Request::create('https://mcp.example.test/mcp/editors')));
        self::assertFalse($guard->isResourcePath(Request::create('https://mcp.example.test/mcp/public')));
    }

    public function testMcpAuthorizeAcceptsAnyConfiguredResourceUri(): void
    {
        $guard = $this->guard(resourcePaths: ['/_mcp', '/mcp/editors']);

        self::assertTrue($guard->isMcpAuthorize(Request::create(
            'https://mcp.example.test/oauth2/authorize?resource=https://mcp.example.test/mcp/editors',
        )));
        self::assertFalse($guard->isMcpAuthorize(Request::create(
            'https://mcp.example.test/oauth2/authorize?resource=https://mcp.example.test/mcp/other',
        )));
    }

    /**
     * @param list<string> $scopes
     * @param list<string> $resourcePaths
     */
    private function guard(array $scopes = ['mcp'], array $resourcePaths = ['/_mcp']): McpRequestGuard
    {
        $settings = new McpOauthSettings(
            resourcePaths: $resourcePaths,
            authorizationPrefix: '/oauth2',
            scopes: $scopes,
            loginRoute: 'app_login',
            consent: 'auto',
            cimdEnabled: true,
            trustedDomains: [],
            dcrEnabled: true,
            resourceIndicators: true,
            issuerIdentification: true,
            publicBaseUrl: 'https://mcp.example.test',
        );
        $canonical = new CanonicalResourceUri();

        return new McpRequestGuard($settings, new IssuerResolver($settings, $canonical), $canonical);
    }
}
