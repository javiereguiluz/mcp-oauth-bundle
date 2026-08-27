<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\OAuth;

use Omouren\McpOauthBundle\OAuth\AuthorizationResponseIssuer;
use PHPUnit\Framework\TestCase;

final class AuthorizationResponseIssuerTest extends TestCase
{
    public function testAddsIssToCodeQuery(): void
    {
        $updated = (new AuthorizationResponseIssuer())->withIssuer(
            'http://127.0.0.1:6274/oauth/callback?code=abc&state=xyz',
            'https://admin.dev.frenchfounders.com',
        );

        self::assertNotNull($updated);
        self::assertSame(
            'http://127.0.0.1:6274/oauth/callback?code=abc&state=xyz&iss=https%3A%2F%2Fadmin.dev.frenchfounders.com',
            $updated,
        );
    }

    public function testAddsIssToErrorQuery(): void
    {
        $updated = (new AuthorizationResponseIssuer())->withIssuer(
            'http://127.0.0.1:6274/oauth/callback?error=access_denied&state=xyz',
            'https://mcp.example.test',
        );

        self::assertNotNull($updated);
        self::assertStringContainsString('error=access_denied', $updated);
        self::assertStringContainsString('iss=https%3A%2F%2Fmcp.example.test', $updated);
    }

    public function testAddsIssToFragmentAuthorizationResponse(): void
    {
        $updated = (new AuthorizationResponseIssuer())->withIssuer(
            'http://127.0.0.1:6274/oauth/callback#code=abc&state=xyz',
            'https://mcp.example.test',
        );

        self::assertNotNull($updated);
        self::assertSame(
            'http://127.0.0.1:6274/oauth/callback#code=abc&state=xyz&iss=https%3A%2F%2Fmcp.example.test',
            $updated,
        );
    }

    public function testLeavesExistingIssUnchanged(): void
    {
        $target = 'http://127.0.0.1:6274/oauth/callback?code=abc&iss=https%3A%2F%2Fmcp.example.test';

        $updated = (new AuthorizationResponseIssuer())->withIssuer($target, 'https://other.example');

        self::assertSame($target, $updated);
    }

    public function testIgnoresInternalLoginRedirect(): void
    {
        $updated = (new AuthorizationResponseIssuer())->withIssuer(
            '/login?_target_path=http%3A%2F%2Flocalhost%2Foauth2%2Fauthorize',
            'https://mcp.example.test',
        );

        self::assertNull($updated);
    }
}
