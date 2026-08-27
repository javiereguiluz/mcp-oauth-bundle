<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle;

final readonly class McpOauthSettings
{
    /**
     * @param list<string> $scopes
     * @param list<string> $trustedDomains
     */
    public function __construct(
        public string $resourcePath,
        public string $authorizationPrefix,
        public array $scopes,
        public string $loginRoute,
        public string $consent,
        public bool $cimdEnabled,
        public array $trustedDomains,
        public bool $dcrEnabled,
        public bool $resourceIndicators,
        public bool $issuerIdentification,
        public ?string $publicBaseUrl,
    ) {
    }
}
