<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\OAuth;

use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\AccessTokenResourceClaims;
use Omouren\McpOauthBundle\OAuth\CanonicalResourceUri;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use PHPUnit\Framework\TestCase;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\RequestStack;

final class AccessTokenResourceClaimsTest extends TestCase
{
    public function testUsesResourceParameterWhenPresent(): void
    {
        $request = Request::create('https://mcp.example.test/oauth2/token', 'POST', [
            'resource' => 'https://mcp.example.test/_mcp',
        ]);
        $stack = new RequestStack();
        $stack->push($request);

        $claims = $this->factory($stack)->claims();

        self::assertSame('https://mcp.example.test/_mcp', $claims['resource']);
        self::assertSame('https://mcp.example.test/_mcp', $claims['aud']);
        self::assertSame('https://mcp.example.test/_mcp', $request->attributes->get(AccessTokenResourceClaims::REQUEST_ATTRIBUTE));
    }

    public function testFallsBackToCanonicalResourceWhenMcpScopeIsPresent(): void
    {
        $request = Request::create('https://mcp.example.test/oauth2/token', 'POST');
        $stack = new RequestStack();
        $stack->push($request);

        $claims = $this->factory($stack)->claims(['mcp']);

        self::assertSame('https://mcp.example.test/_mcp', $claims['resource']);
    }

    public function testReturnsNothingForUnrelatedTokenRequest(): void
    {
        $stack = new RequestStack();
        $stack->push(Request::create('https://mcp.example.test/oauth2/token', 'POST', [
            'grant_type' => 'client_credentials',
        ]));

        self::assertSame([], $this->factory($stack)->claims(['api']));
    }

    public function testReturnsNothingWhenResourceIndicatorsAreOff(): void
    {
        $stack = new RequestStack();
        $stack->push(Request::create('https://mcp.example.test/oauth2/token', 'POST', [
            'resource' => 'https://mcp.example.test/_mcp',
        ]));

        $claims = $this->factory($stack, resourceIndicators: false)->claims();

        self::assertSame([], $claims);
    }

    private function factory(RequestStack $stack, bool $resourceIndicators = true): AccessTokenResourceClaims
    {
        $settings = new McpOauthSettings(
            ['/_mcp'],
            '/oauth2',
            ['mcp'],
            'app_login',
            'page',
            true,
            ['claude.ai'],
            true,
            $resourceIndicators,
            true,
            'https://mcp.example.test',
        );
        $canonical = new CanonicalResourceUri();
        $issuerResolver = new IssuerResolver($settings, $canonical);

        return new AccessTokenResourceClaims(
            $settings,
            $stack,
            $issuerResolver,
            new McpRequestGuard($settings, $issuerResolver, $canonical),
        );
    }
}
