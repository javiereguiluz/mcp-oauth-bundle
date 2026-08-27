<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\DependencyInjection;

use Symfony\Component\DependencyInjection\Compiler\CompilerPassInterface;
use Symfony\Component\DependencyInjection\ContainerBuilder;
use Symfony\Component\DependencyInjection\Reference;

/**
 * League 0.10 has no extra-claims event: decorate the access-token repository to emit RFC 8707 claims.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8707
 */
final class LeagueCompatibilityPass implements CompilerPassInterface
{
    public function process(ContainerBuilder $container): void
    {
        if (class_exists(\League\Bundle\OAuth2ServerBundle\Event\AccessTokenExtraClaimsResolveEvent::class)) {
            return;
        }

        if (!$container->has('league.oauth2_server.repository.access_token')) {
            return;
        }

        $id = AccessTokenRepositoryDecorator::class;
        $container->register($id, $id)
            ->setAutowired(true)
            ->setDecoratedService('league.oauth2_server.repository.access_token')
            ->setArgument('$inner', new Reference($id.'.inner'));
    }
}
