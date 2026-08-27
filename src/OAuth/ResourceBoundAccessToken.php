<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\OAuth;

use DateTimeImmutable;
use Lcobucci\JWT\Builder;
use Lcobucci\JWT\Token\RegisteredClaims;
use League\OAuth2\Server\Entities\AccessTokenEntityInterface;
use League\OAuth2\Server\Entities\Traits\AccessTokenTrait;
use League\OAuth2\Server\Entities\Traits\EntityTrait;
use League\OAuth2\Server\Entities\Traits\TokenEntityTrait;

/**
 * League 0.10 has no ACCESS_TOKEN_EXTRA_CLAIMS_RESOLVE event. This entity
 * injects RFC 8707 claims the same way League 1.2+ does in its AccessToken.
 *
 * `aud` is a registered JWT claim: lcobucci/jwt rejects Builder::withClaim('aud').
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8707
 */
final class ResourceBoundAccessToken implements AccessTokenEntityInterface
{
    use AccessTokenTrait;
    use EntityTrait;
    use TokenEntityTrait;

    /**
     * @param array<string, mixed> $extraClaims
     */
    public function __construct(
        private array $extraClaims = [],
    ) {
    }

    public function toString(): string
    {
        $this->initJwtConfiguration();

        $builder = $this->jwtConfiguration->builder()
            ->permittedFor(...$this->audiences())
            ->identifiedBy($this->getIdentifier())
            ->issuedAt(new DateTimeImmutable())
            ->canOnlyBeUsedAfter(new DateTimeImmutable())
            ->expiresAt($this->getExpiryDateTime())
            ->relatedTo($this->getUserIdentifier() ?? $this->getClient()->getIdentifier())
            ->withClaim('scopes', $this->getScopes());

        return $this->withCustomClaims($builder)
            ->getToken($this->jwtConfiguration->signer(), $this->jwtConfiguration->signingKey())
            ->toString();
    }

    private function withCustomClaims(Builder $builder): Builder
    {
        foreach ($this->extraClaims as $name => $value) {
            if (!\is_string($name) || '' === $name || 'scopes' === $name) {
                continue;
            }

            // Builder::withClaim() rejects every registered claim.
            if (\in_array($name, RegisteredClaims::ALL, true)) {
                continue;
            }

            $builder = $builder->withClaim($name, $value);
        }

        return $builder;
    }

    /**
     * @return list<non-empty-string>
     */
    private function audiences(): array
    {
        $value = $this->extraClaims[RegisteredClaims::AUDIENCE] ?? $this->extraClaims['resource'] ?? null;
        $audiences = [];
        foreach (\is_array($value) ? $value : [$value] as $audience) {
            if (\is_string($audience) && '' !== $audience) {
                $audiences[] = $audience;
            }
        }

        if ([] === $audiences) {
            $audiences[] = $this->getClient()->getIdentifier();
        }

        return $audiences;
    }
}
