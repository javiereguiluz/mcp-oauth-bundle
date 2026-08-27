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
 * Copies mcp-bundle `mcp.http.path` into this bundle as the protected MCP resource path.
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

        $path = $this->httpPath($container);

        $container->setParameter('mcp_oauth.resource_path', $path);
        $container->getDefinition(McpOauthSettings::class)->setArgument('$resourcePath', $path);
    }

    private function httpPath(ContainerBuilder $container): string
    {
        $config = $this->mcpConfig($container);

        if (true !== ($config['client_transports']['http'] ?? false)) {
            throw new LogicException('MCP OAuth protects the MCP HTTP endpoint, so "mcp.client_transports.http" must be enabled.');
        }

        $path = $config['http']['path'] ?? null;
        if (!\is_string($path) || '' === $path) {
            throw new LogicException('Unable to read "mcp.http.path" from symfony/mcp-bundle.');
        }

        return rtrim($path, '/') ?: '/';
    }

    /**
     * @return array<string, mixed>
     */
    private function mcpConfig(ContainerBuilder $container): array
    {
        $extension = $container->hasExtension(self::EXTENSION) ? $container->getExtension(self::EXTENSION) : null;
        if (!$extension instanceof ConfigurationExtensionInterface) {
            throw new LogicException('MCP OAuth reads the MCP HTTP path from symfony/mcp-bundle, which is not registered.');
        }

        
        $configs = $container->getParameterBag()->resolveValue($container->getExtensionConfig(self::EXTENSION));
        $configuration = $extension->getConfiguration($configs, $container);
        if (null === $configuration) {
            throw new LogicException('The "mcp" extension does not expose a configuration tree.');
        }

        return (new Processor())->processConfiguration($configuration, $configs);
    }
}
