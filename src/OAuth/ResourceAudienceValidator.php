<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\OAuth;

final class ResourceAudienceValidator
{
    public function __construct(
        private CanonicalResourceUri $canonicalResourceUri,
    ) {
    }

    /**
     * @param array<string, mixed> $claims
     */
    public function tokenTargetsResource(array $claims, string $expectedResource): bool
    {
        $candidates = [];
        if (isset($claims['resource']) && \is_string($claims['resource'])) {
            $candidates[] = $claims['resource'];
        }

        $aud = $claims['aud'] ?? null;
        if (\is_string($aud)) {
            $candidates[] = $aud;
        }
        if (\is_array($aud)) {
            foreach ($aud as $value) {
                if (\is_string($value)) {
                    $candidates[] = $value;
                }
            }
        }

        foreach ($candidates as $candidate) {
            if ($this->canonicalResourceUri->matches($expectedResource, $candidate)) {
                return true;
            }
        }

        return false;
    }
}
