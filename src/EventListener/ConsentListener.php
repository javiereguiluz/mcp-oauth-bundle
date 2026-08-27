<?php

declare(strict_types=1);

namespace Omouren\McpOauthBundle\EventListener;

use League\Bundle\OAuth2ServerBundle\Event\AuthorizationRequestResolveEvent;
use League\Bundle\OAuth2ServerBundle\OAuth2Events;
use Omouren\McpOauthBundle\McpOauthSettings;
use Omouren\McpOauthBundle\OAuth\McpRequestGuard;
use Symfony\Component\EventDispatcher\Attribute\AsEventListener;
use Symfony\Component\HttpFoundation\RedirectResponse;
use Symfony\Component\HttpFoundation\RequestStack;
use Symfony\Component\Routing\Generator\UrlGeneratorInterface;

#[AsEventListener(event: OAuth2Events::AUTHORIZATION_REQUEST_RESOLVE)]
final readonly class ConsentListener
{
    public function __construct(
        private McpOauthSettings $settings,
        private RequestStack $requestStack,
        private UrlGeneratorInterface $urlGenerator,
        private McpRequestGuard $mcpRequestGuard,
    ) {
    }

    public function __invoke(AuthorizationRequestResolveEvent $event): void
    {
        $request = $this->requestStack->getCurrentRequest();
        if (null === $request || !$this->mcpRequestGuard->isAuthorizePath($request)) {
            return;
        }

        if (!$this->mcpRequestGuard->targetsMcp($request, $event->getScopes())) {
            return;
        }

        if ('auto' === $this->settings->consent) {
            $event->resolveAuthorization(AuthorizationRequestResolveEvent::AUTHORIZATION_APPROVED);

            return;
        }

        if (!$request->hasSession()) {
            return;
        }

        if (true === $request->getSession()->get('mcp_oauth.consent_approved')) {
            $request->getSession()->remove('mcp_oauth.consent_approved');
            $event->resolveAuthorization(AuthorizationRequestResolveEvent::AUTHORIZATION_APPROVED);

            return;
        }

        $query = $request->query->all();
        $query['client_name'] = $event->getClient()->getName();
        $redirectUri = $event->getRedirectUri();
        $query['redirect_host'] = \is_string($redirectUri) ? (parse_url($redirectUri, \PHP_URL_HOST) ?: '') : '';

        $event->setResponse(new RedirectResponse($this->urlGenerator->generate('mcp_oauth_consent', $query)));
    }
}
