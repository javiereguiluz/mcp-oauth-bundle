<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\EventListener;

use Omouren\McpOauthBundle\Cimd\CimdException;
use Omouren\McpOauthBundle\Cimd\ClientIdMetadataResolver;
use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\LeagueClientSynchronizer;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\JsonResponse;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpKernel\Event\RequestEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * CIMD: rewrite an HTTPS URL `client_id` before League sees it (identifier column is VARCHAR(32)).
 *
 * @see https://datatracker.ietf.org/doc/html/draft-ietf-oauth-client-id-metadata-document-00
 */
#[AsEventListener(event: KernelEvents::REQUEST, priority: 16)]
final readonly class CimdRequestListener
{
    public function __construct(
        private McpOauthSettings $settings,
        private ClientIdMetadataResolver $resolver,
        private McpRequestGuard $mcpRequestGuard,
        private ?LeagueClientSynchronizer $clientSynchronizer = null,
    ) {
    }

    public function __invoke(RequestEvent $event): void
    {
        if (!$event->isMainRequest() || !$this->settings->cimdEnabled) {
            return;
        }

        $request = $event->getRequest();
        if (!$this->mcpRequestGuard->isMcpAuthorize($request) && !$this->mcpRequestGuard->isMcpToken($request)) {
            return;
        }

        $clientId = $this->clientId($request);
        if (null === $clientId || !str_starts_with($clientId, 'https://')) {
            return;
        }

        try {
            $document = $this->resolver->resolve($clientId);
            $identifier = $this->clientSynchronizer?->persistFromCimd($clientId, $document)
                ?? LeagueClientSynchronizer::hashClientId($clientId);
        } catch (CimdException $e) {
            $event->setResponse(new JsonResponse([
                'error' => 'invalid_client',
                'error_description' => $e->getMessage(),
            ], 400));

            return;
        }

        $request->attributes->set('mcp_oauth.original_client_id', $clientId);
        $request->attributes->set('mcp_oauth.client_name', $document->clientName);
        $request->attributes->set('mcp_oauth.redirect_uris', $document->redirectUris);
        $request->query->set('client_id', $identifier);
        $request->request->set('client_id', $identifier);
    }

    private function clientId(Request $request): ?string
    {
        $value = $request->query->get('client_id') ?? $request->request->get('client_id');

        return \is_string($value) && '' !== $value ? $value : null;
    }
}
