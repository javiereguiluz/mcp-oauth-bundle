<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\OAuth;

use Omouren\McpOauthBundle\OAuth\WwwAuthenticateHeader;
use PHPUnit\Framework\TestCase;

final class WwwAuthenticateHeaderTest extends TestCase
{
    public function testFormatIncludesMetadataAndScope(): void
    {
        $header = (new WwwAuthenticateHeader())->format(
            'https://mcp.example.test/.well-known/oauth-protected-resource/_mcp',
            ['mcp'],
            'insufficient_scope',
        );

        self::assertStringContainsString('Bearer ', $header);
        self::assertStringContainsString('resource_metadata="https://mcp.example.test/.well-known/oauth-protected-resource/_mcp"', $header);
        self::assertStringContainsString('scope="mcp"', $header);
        self::assertStringContainsString('error="insufficient_scope"', $header);
    }
}
