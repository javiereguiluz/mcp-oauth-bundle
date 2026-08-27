<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\Controller;

use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;

final readonly class ProtectedResourceMetadataController
{
    public function __construct(
        private McpOauthSettings $settings,
        private IssuerResolver $issuerResolver,
    ) {
    }

    public function __invoke(Request $request): JsonResponse
    {
        $response = new JsonResponse([
            'resource' => $this->issuerResolver->resource($request),
            'authorization_servers' => [$this->issuerResolver->issuer($request)],
            'bearer_methods_supported' => ['header'],
            'scopes_supported' => $this->settings->scopes,
        ]);
        $response->headers->set('Access-Control-Allow-Origin', '*');
        $response->headers->set('Cache-Control', 'public, max-age=3600');

        return $response;
    }
}
