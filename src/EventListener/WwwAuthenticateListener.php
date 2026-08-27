<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\EventListener;

use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use Omouren\McpOauthBundle\OAuth\WwwAuthenticateHeader;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

#[AsEventListener(event: KernelEvents::RESPONSE, priority: 0)]
final readonly class WwwAuthenticateListener
{
    public function __construct(
        private McpOauthSettings $settings,
        private IssuerResolver $issuerResolver,
        private WwwAuthenticateHeader $wwwAuthenticateHeader,
        private McpRequestGuard $mcpRequestGuard,
    ) {
    }

    public function __invoke(ResponseEvent $event): void
    {
        if (!$event->isMainRequest()) {
            return;
        }

        $request = $event->getRequest();
        if (!$this->mcpRequestGuard->isResourcePath($request)) {
            return;
        }

        $response = $event->getResponse();
        $status = $response->getStatusCode();
        if (Response::HTTP_UNAUTHORIZED !== $status && Response::HTTP_FORBIDDEN !== $status) {
            return;
        }

        $error = null;
        if (Response::HTTP_FORBIDDEN === $status) {
            $error = 'insufficient_scope';
        } elseif (str_starts_with($request->headers->get('Authorization', ''), 'Bearer ')) {
            $error = 'invalid_token';
        }
        $header = $this->wwwAuthenticateHeader->format(
            $this->issuerResolver->protectedResourceMetadataUrl($request),
            $this->settings->scopes,
            $error,
        );
        $response->headers->set('WWW-Authenticate', $header);
        $response->headers->set('Access-Control-Expose-Headers', 'WWW-Authenticate');
        $response->headers->remove('Mcp-Session-Id');
    }
}
