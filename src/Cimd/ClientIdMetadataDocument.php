<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Cimd;

final readonly class ClientIdMetadataDocument
{
    /**
     * @param list<string> $redirectUris
     */
    public function __construct(
        public string $clientId,
        public string $clientName,
        public array $redirectUris,
    ) {
    }
}
