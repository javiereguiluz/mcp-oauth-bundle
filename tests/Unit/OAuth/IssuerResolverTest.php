<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\OAuth;

use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\CanonicalResourceUri;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;

final class IssuerResolverTest extends TestCase
{
    public function testResourceFallsBackToTheFirstPathOnAuthorize(): void
    {
        $resolver = $this->resolver(['/_mcp', '/mcp/editors']);
        $request = Request::create('https://mcp.example.test/oauth2/authorize?scope=mcp');

        self::assertSame('https://mcp.example.test/_mcp', $resolver->resource($request));
        self::assertSame([
            'https://mcp.example.test/_mcp',
            'https://mcp.example.test/mcp/editors',
        ], $resolver->resources($request));
    }

    public function testResourceUsesTheMatchingHttpPath(): void
    {
        $resolver = $this->resolver(['/_mcp', '/mcp/editors']);
        $request = Request::create('https://mcp.example.test/mcp/editors');

        self::assertSame('https://mcp.example.test/mcp/editors', $resolver->resource($request));
        self::assertSame(
            'https://mcp.example.test/.well-known/oauth-protected-resource/mcp/editors',
            $resolver->protectedResourceMetadataUrl($request),
        );
    }

    public function testResourceUsesTheWellKnownPathAttribute(): void
    {
        $resolver = $this->resolver(['/_mcp', '/mcp/editors']);
        $request = Request::create('https://mcp.example.test/.well-known/oauth-protected-resource/mcp/editors');
        $request->attributes->set('path', 'mcp/editors');

        self::assertSame('https://mcp.example.test/mcp/editors', $resolver->resource($request));
    }

    /**
     * @param list<string> $resourcePaths
     */
    private function resolver(array $resourcePaths): IssuerResolver
    {
        $settings = new McpOauthSettings(
            resourcePaths: $resourcePaths,
            authorizationPrefix: '/oauth2',
            scopes: ['mcp'],
            loginRoute: 'app_login',
            redirectQueryParam: '_target_path',
            consent: 'auto',
            cimdEnabled: true,
            trustedDomains: [],
            dcrEnabled: true,
            resourceIndicators: true,
            issuerIdentification: true,
            publicBaseUrl: 'https://mcp.example.test',
        );

        return new IssuerResolver($settings, new CanonicalResourceUri());
    }
}
