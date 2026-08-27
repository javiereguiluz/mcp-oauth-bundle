<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\OAuth;

final class WwwAuthenticateHeader
{
    /**
     * @param list<string> $scopes
     */
    public function format(string $resourceMetadataUrl, array $scopes, ?string $error = null): string
    {
        $parts = [
            \sprintf('resource_metadata="%s"', $resourceMetadataUrl),
        ];

        if ([] !== $scopes) {
            $parts[] = \sprintf('scope="%s"', implode(' ', $scopes));
        }

        if (null !== $error && '' !== $error) {
            $parts[] = \sprintf('error="%s"', $error);
        }

        return 'Bearer '.implode(', ', $parts);
    }
}
