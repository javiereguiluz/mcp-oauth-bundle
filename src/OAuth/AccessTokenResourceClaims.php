<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\OAuth;

use Omouren\McpOauthBundle\McpOauthSettings;
use Symfony\Component\HttpFoundation\RequestStack;

final readonly class AccessTokenResourceClaims
{
    public const REQUEST_ATTRIBUTE = 'mcp_oauth.resource';

    public function __construct(
        private McpOauthSettings $settings,
        private RequestStack $requestStack,
        private IssuerResolver $issuerResolver,
        private McpRequestGuard $mcpRequestGuard,
    ) {
    }

    /**
     * @param iterable<mixed> $scopes
     *
     * @return array<string, string>
     */
    public function claims(iterable $scopes = []): array
    {
        if (!$this->settings->resourceIndicators) {
            return [];
        }

        $request = $this->requestStack->getCurrentRequest();
        if (null === $request || !$this->mcpRequestGuard->isMcpToken($request, $scopes)) {
            return [];
        }

        $fromRequest = $request->query->get('resource') ?? $request->request->get('resource');
        $resource = \is_string($fromRequest) && '' !== $fromRequest
            ? $fromRequest
            : $this->issuerResolver->resource($request);

        $request->attributes->set(self::REQUEST_ATTRIBUTE, $resource);

        if ('' === $resource) {
            return [];
        }

        return [
            'resource' => $resource,
            'aud' => $resource,
        ];
    }
}
