<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\DependencyInjection;

use Omouren\McpOauthBundle\McpOauthSettings;
use Symfony\Component\Config\Definition\Processor;
use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Exception\LogicException;
use Symfony\Component\DependencyInjection\Extension\ConfigurationExtensionInterface;

/**
 * Copies mcp-bundle HTTP server paths into this bundle as the protected MCP resource paths.
 *
 * @see https://github.com/symfony/mcp-bundle
 */
final class McpHttpPathPass implements CompilerPassInterface
{
    private const EXTENSION = 'mcp';

    public function process(ContainerBuilder $container): void
    {
        if (!$container->hasDefinition(McpOauthSettings::class)) {
            return;
        }

        $paths = self::httpPathsFromConfig($this->mcpConfig($container));

        $container->getDefinition(McpOauthSettings::class)->setArgument('$resourcePaths', $paths);
    }

    /**
     * @param array<string, mixed> $config Processed `mcp` extension config
     *
     * @return list<string>
     */
    public static function httpPathsFromConfig(array $config): array
    {
        $servers = $config['servers'] ?? [];
        if (!\is_array($servers) || [] === $servers) {
            throw new LogicException('MCP OAuth protects MCP HTTP endpoints, so at least one "mcp.servers" entry with HTTP transport must be configured.');
        }

        $paths = [];
        foreach ($servers as $name => $server) {
            if (!\is_array($server) || true !== ($server['transports']['http'] ?? false)) {
                continue;
            }

            $path = $server['http']['path'] ?? '/mcp/'.$name;
            if (!\is_string($path) || '' === $path) {
                throw new LogicException(\sprintf('Unable to read "mcp.servers.%s.http.path" from symfony/mcp-bundle.', (string) $name));
            }

            $paths[] = rtrim($path, '/') ?: '/';
        }

        if ([] === $paths) {
            throw new LogicException('MCP OAuth protects the MCP HTTP endpoint, so at least one server must enable "transports.http".');
        }

        return array_values(array_unique($paths));
    }

    /**
     * @return array<string, mixed>
     */
    private function mcpConfig(ContainerBuilder $container): array
    {
        $extension = $container->hasExtension(self::EXTENSION) ? $container->getExtension(self::EXTENSION) : null;
        if (!$extension instanceof ConfigurationExtensionInterface) {
            throw new LogicException('MCP OAuth reads MCP HTTP paths from symfony/mcp-bundle, which is not registered.');
        }

        $configs = $container->getParameterBag()->resolveValue($container->getExtensionConfig(self::EXTENSION));
        $configuration = $extension->getConfiguration($configs, $container);
        if (null === $configuration) {
            throw new LogicException('The "mcp" extension does not expose a configuration tree.');
        }

        return (new Processor())->processConfiguration($configuration, $configs);
    }
}
