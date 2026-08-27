<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\EventListener;

use Lcobucci\JWT\Token\RegisteredClaims;
use Omouren\McpOauthBundle\OAuth\AccessTokenResourceClaims;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;

/**
 * League 1.2+: injects RFC 8707 `resource` on MCP access tokens (`aud` is a registered JWT claim).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc8707
 */
#[AsEventListener(event: 'league.oauth2_server.event.access_token_extra_claims_resolve')]
final readonly class AccessTokenAudienceListener
{
    public function __construct(
        private AccessTokenResourceClaims $resourceClaims,
    ) {
    }

    public function __invoke(object $event): void
    {
        if (!method_exists($event, 'setExtraClaims')) {
            return;
        }

        $scopes = [];
        if (method_exists($event, 'getScopes')) {
            $resolved = $event->getScopes();
            if (\is_iterable($resolved)) {
                $scopes = $resolved;
            }
        }

        // League builds extra claims with Builder::withClaim(), which rejects
        // registered claims such as "aud". The resource binding is carried by
        // the "resource" claim, and ResourceAudienceValidator accepts either.
        $claims = array_diff_key(
            $this->resourceClaims->claims($scopes),
            array_flip(RegisteredClaims::ALL),
        );

        if ([] === $claims) {
            return;
        }

        $event->setExtraClaims($claims);
    }
}
