<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\OAuth;

final class JwtClaimReader
{
    /**
     * @return array<string, mixed>|null
     */
    public function payload(string $jwt): ?array
    {
        $parts = explode('.', $jwt);
        if (3 !== \count($parts)) {
            return null;
        }

        $decoded = base64_decode(strtr($parts[1], '-_', '+/'), true);
        if (false === $decoded) {
            return null;
        }

        $payload = json_decode($decoded, true);
        if (!\is_array($payload)) {
            return null;
        }

        
        return $payload;
    }
}
