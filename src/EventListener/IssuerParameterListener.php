<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\EventListener;

use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\AuthorizationResponseIssuer;
use Omouren\McpOauthBundle\OAuth\IssuerResolver;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpKernel\Event\ResponseEvent;
use Symfony\Component\HttpKernel\KernelEvents;

/**
 * RFC 9207: append `iss` on MCP authorization redirects (any 3xx Location, not only RedirectResponse).
 *
 * @see https://datatracker.ietf.org/doc/html/rfc9207
 */
#[AsEventListener(event: KernelEvents::RESPONSE, priority: -16)]
final readonly class IssuerParameterListener
{
    public function __construct(
        private McpOauthSettings $settings,
        private IssuerResolver $issuerResolver,
        private McpRequestGuard $mcpRequestGuard,
        private AuthorizationResponseIssuer $authorizationResponseIssuer = new AuthorizationResponseIssuer(),
    ) {
    }

    public function __invoke(ResponseEvent $event): void
    {
        if (!$event->isMainRequest() || !$this->settings->issuerIdentification) {
            return;
        }

        $request = $event->getRequest();
        if (!$this->mcpRequestGuard->isMcpAuthorize($request)) {
            return;
        }

        $response = $event->getResponse();
        $status = $response->getStatusCode();
        if ($status < 300 || $status >= 400) {
            return;
        }

        $target = $response->headers->get('Location');
        if (!\is_string($target) || '' === $target) {
            return;
        }

        $updated = $this->authorizationResponseIssuer->withIssuer(
            $target,
            $this->issuerResolver->issuer($request),
        );
        if (null === $updated || $updated === $target) {
            return;
        }

        if ($response instanceof RedirectResponse) {
            $response->setTargetUrl($updated);
        }
        $response->headers->set('Location', $updated);
    }
}
