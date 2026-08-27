<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\DependencyInjection;

use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\ClientEntityInterface;
use League\OAuth2\Server\Repositories\AccessTokenRepositoryInterface;
use Omouren\McpOauthBundle\OAuth\AccessTokenResourceClaims;
use Omouren\McpOauthBundle\OAuth\ResourceBoundAccessToken;

/**
 * Used on League 0.10, which cannot dispatch extra JWT claims.
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8707
 */
final readonly class AccessTokenRepositoryDecorator implements AccessTokenRepositoryInterface
{
    public function __construct(
        private AccessTokenRepositoryInterface $inner,
        private AccessTokenResourceClaims $resourceClaims,
    ) {
    }

    public function getNewToken(ClientEntityInterface $clientEntity, array $scopes, ?string $userIdentifier = null): AccessTokenEntityInterface
    {
        $claims = $this->resourceClaims->claims($scopes);
        if ([] === $claims) {
            return $this->inner->getNewToken($clientEntity, $scopes, $userIdentifier);
        }

        $accessToken = new ResourceBoundAccessToken($claims);
        $accessToken->setClient($clientEntity);
        if (null !== $userIdentifier && '' !== $userIdentifier) {
            $accessToken->setUserIdentifier($userIdentifier);
        }
        foreach ($scopes as $scope) {
            $accessToken->addScope($scope);
        }

        return $accessToken;
    }

    public function persistNewAccessToken(AccessTokenEntityInterface $accessTokenEntity): void
    {
        $this->inner->persistNewAccessToken($accessTokenEntity);
    }

    public function revokeAccessToken(string $tokenId): void
    {
        $this->inner->revokeAccessToken($tokenId);
    }

    public function isAccessTokenRevoked(string $tokenId): bool
    {
        return $this->inner->isAccessTokenRevoked($tokenId);
    }
}
