<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Tests\Unit\DependencyInjection;

use Omouren\McpOauthBundle\DependencyInjection\McpHttpPathPass;
use PHPUnit\Framework\TestCase;
use Symfony\Component\DependencyInjection\Exception\LogicException;

final class McpHttpPathPassTest extends TestCase
{
    public function testCollectsASingleHttpServerPath(): void
    {
        $paths = McpHttpPathPass::httpPathsFromConfig([
            'servers' => [
                'default' => [
                    'transports' => ['http' => true],
                    'http' => ['path' => '/_mcp'],
                ],
            ],
        ]);

        self::assertSame(['/_mcp'], $paths);
    }

    public function testCollectsEveryHttpServerPath(): void
    {
        $paths = McpHttpPathPass::httpPathsFromConfig([
            'servers' => [
                'public' => [
                    'transports' => ['http' => true],
                    'http' => ['path' => '/mcp'],
                ],
                'editors' => [
                    'transports' => ['http' => true],
                    'http' => ['path' => '/mcp/editors/'],
                ],
                'stdio' => [
                    'transports' => ['http' => false, 'stdio' => true],
                ],
            ],
        ]);

        self::assertSame(['/mcp', '/mcp/editors'], $paths);
    }

    public function testDefaultsPathFromServerNameWhenUnset(): void
    {
        $paths = McpHttpPathPass::httpPathsFromConfig([
            'servers' => [
                'default' => [
                    'transports' => ['http' => true],
                    'http' => [],
                ],
            ],
        ]);

        self::assertSame(['/mcp/default'], $paths);
    }

    public function testRejectsAnEmptyServerMap(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('mcp.servers');

        McpHttpPathPass::httpPathsFromConfig(['servers' => []]);
    }

    public function testRejectsWhenNoServerEnablesHttp(): void
    {
        $this->expectException(LogicException::class);
        $this->expectExceptionMessage('transports.http');

        McpHttpPathPass::httpPathsFromConfig([
            'servers' => [
                'cli' => [
                    'transports' => ['http' => false, 'stdio' => true],
                ],
            ],
        ]);
    }
}
