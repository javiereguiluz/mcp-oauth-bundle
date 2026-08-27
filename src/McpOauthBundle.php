<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle;

use Omouren\McpOauthBundle\DependencyInjection\LeagueCompatibilityPass;
use Omouren\McpOauthBundle\DependencyInjection\McpHttpPathPass;
use Symfony\Component\Config\Definition\Configurator\DefinitionConfigurator;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Loader\Configurator\ContainerConfigurator;
use Symfony\Component\HttpKernel\Bundle\AbstractBundle;

final class McpOauthBundle extends AbstractBundle
{
    public function configure(DefinitionConfigurator $definition): void
    {
        $definition->import('../config/definition.php');
    }

    /**
     * @param array<string, mixed> $config
     */
    public function loadExtension(array $config, ContainerConfigurator $container, ContainerBuilder $builder): void
    {
        $prefix = rtrim((string) $config['authorization_prefix'], '/');
        $builder->setParameter('mcp_oauth.authorization_prefix', $prefix);

        // $resourcePath comes from mcp.http.path, resolved by McpHttpPathPass.
        $builder->register(McpOauthSettings::class)
            ->setArguments([
                '$authorizationPrefix' => $prefix,
                '$scopes' => $config['scopes'],
                '$loginRoute' => $config['login_route'],
                '$consent' => $config['consent'],
                '$cimdEnabled' => $config['cimd']['enabled'],
                '$trustedDomains' => $config['cimd']['trusted_domains'],
                '$dcrEnabled' => $config['dcr']['enabled'],
                '$resourceIndicators' => $config['resource_indicators'],
                '$issuerIdentification' => $config['issuer_identification'],
                '$publicBaseUrl' => $config['public_base_url'],
            ]);

        $container->import('../config/services.yaml');
    }

    public function build(ContainerBuilder $container): void
    {
        $container->addCompilerPass(new McpHttpPathPass());
        $container->addCompilerPass(new LeagueCompatibilityPass());
    }
}
