<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\OAuth;

use Omouren\McpOauthBundle\OAuth\CanonicalResourceUri;
use PHPUnit\Framework\TestCase;

final class CanonicalResourceUriTest extends TestCase
{
    public function testCombineAndMatchIgnoreCaseAndTrailingSlash(): void
    {
        $canonical = new CanonicalResourceUri();

        self::assertSame('https://mcp.example.test/_mcp', $canonical->combine('https://mcp.example.test/', '/_mcp'));
        self::assertTrue($canonical->matches('https://mcp.example.test/_mcp', 'HTTPS://MCP.EXAMPLE.TEST/_mcp'));
        self::assertFalse($canonical->matches('https://mcp.example.test/_mcp', 'https://mcp.example.test/_mcp/other'));
    }
}
